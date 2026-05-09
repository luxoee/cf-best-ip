#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
best_ip_online_two_stage.py

在线优选 Cloudflare IP 的核心 Python 实现。

核心能力：
1. 从 Cloudflare IPv4 / IPv6 CIDR 随机生成候选 IP
2. 同时测试多个 HTTPS 端口：443 / 2053 / 2083 / 2087 / 2096 / 8443
3. 第一阶段：TCP connect 快速筛选
4. 第二阶段：TLS + HTTP 精测，多次采样取中位数
5. 每个端口输出延迟最低的 Top N
6. 输出格式兼容 edgetunnel：IP:端口#延迟ms

只使用 Python 标准库，无第三方依赖。

运行示例：
    python3 best_ip_online_two_stage.py

    python3 best_ip_online_two_stage.py --count 2048 --top 16

    python3 best_ip_online_two_stage.py --ipv6

    python3 best_ip_online_two_stage.py --ports 443,2053,2083,2087,2096,8443

    python3 best_ip_online_two_stage.py --output bestip.txt

适合学习的 Python 高级技巧：
- dataclass
- slots
- frozen dataclass
- asyncio.Queue
- asyncio.create_task
- asyncio.wait_for
- async worker pool
- heapq.nsmallest
- statistics.median
- argparse
- ipaddress
- ssl.SSLContext 复用
"""

from __future__ import annotations

import argparse
import asyncio
import heapq
import ipaddress
import random
import ssl
import statistics
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable, TypeVar


# -----------------------------------------------------------------------------
# 1. 默认 Cloudflare IP 段
# -----------------------------------------------------------------------------

CF_IPV4_CIDRS = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

CF_IPV6_CIDRS = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]

DEFAULT_PORTS = [443, 2053, 2083, 2087, 2096, 8443]


# -----------------------------------------------------------------------------
# 2. 数据结构
# -----------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Target:
    """
    一个待测试目标。

    frozen=True:
        创建后不可修改，避免异步环境中被意外改动。

    slots=True:
        减少对象内存占用。大量 IP:PORT 任务时很有用。
    """
    ip: str
    port: int


@dataclass(frozen=True, slots=True)
class TcpProbeResult:
    """第一阶段 TCP 快筛结果。"""
    ip: str
    port: int
    latency_ms: float


@dataclass(frozen=True, slots=True)
class HttpProbeResult:
    """第二阶段 TLS + HTTP 精测结果。"""
    ip: str
    port: int
    latency_ms: float
    samples: tuple[float, ...]
    status_codes: tuple[int, ...]

    @property
    def ip_for_url(self) -> str:
        """IPv6 在 URI / 配置里通常需要方括号。"""
        return f"[{self.ip}]" if ":" in self.ip else self.ip

    @property
    def edgetunnel_line(self) -> str:
        """edgetunnel ADD.txt / 自定义优选 IP 常用格式。"""
        return f"{self.ip_for_url}:{self.port}#{self.latency_ms:.0f}ms"

    @property
    def debug_line(self) -> str:
        sample_text = ",".join(f"{x:.0f}" for x in self.samples)
        status_text = ",".join(str(x) for x in self.status_codes)
        return (
            f"{self.edgetunnel_line}"
            f"    samples=[{sample_text}]"
            f"    status=[{status_text}]"
        )


@dataclass(slots=True)
class QueueStats:
    """任务队列统计信息。"""
    total: int
    done: int = 0
    success: int = 0
    failed: int = 0

    @property
    def percent(self) -> float:
        if self.total == 0:
            return 100.0
        return self.done / self.total * 100


T = TypeVar("T")


# -----------------------------------------------------------------------------
# 3. IP 生成逻辑
# -----------------------------------------------------------------------------

def random_ip_from_cidr(cidr: str) -> str:
    """
    从 CIDR 中随机取一个 IP。

    注意：
    IPv6 段非常大，不能使用 list(network.hosts())。
    正确做法是：随机生成一个整数偏移量，再加到 network_address 上。
    """
    network = ipaddress.ip_network(cidr, strict=False)

    if network.num_addresses <= 2:
        return str(network.network_address)

    # IPv6 地址空间巨大，随机整个空间没有必要。
    # 限制偏移范围可以保持速度，同时仍然有足够随机性。
    max_offset = min(network.num_addresses - 2, 2**32 - 1)
    offset = random.randint(1, max_offset)

    return str(network.network_address + offset)


def build_candidate_ips(cidrs: Iterable[str], count: int) -> list[str]:
    """
    从多个 CIDR 中生成不重复候选 IP。

    参数：
        cidrs: IP 段列表
        count: 生成数量
    """
    cidr_list = list(cidrs)

    if not cidr_list:
        raise ValueError("CIDR 列表不能为空")

    ips: set[str] = set()

    while len(ips) < count:
        cidr = random.choice(cidr_list)
        ips.add(random_ip_from_cidr(cidr))

    return list(ips)


def load_ips_from_file(path: str) -> list[str]:
    """
    从文件读取候选 IP。

    支持格式：
        104.18.38.47
        104.18.38.47:443
        104.18.38.47:443#remark
        [2606:4700::6812:2a62]
        [2606:4700::6812:2a62]:443#remark

    这里只提取 IP，端口由 --ports 统一控制。
    """
    ips: set[str] = set()

    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            # 去掉备注
            line = line.split("#", 1)[0].strip()

            if line.startswith("["):
                # IPv6: [2606:4700::1]:443
                end = line.find("]")
                if end == -1:
                    continue
                ip = line[1:end]
            else:
                # IPv4: 104.18.38.47:443
                # 域名不处理，本工具专注 IP 优选
                ip = line.split(":", 1)[0].strip()

            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue

            ips.add(ip)

    return list(ips)


# -----------------------------------------------------------------------------
# 4. SSL / HTTP 辅助函数
# -----------------------------------------------------------------------------

def build_ssl_context() -> ssl.SSLContext:
    """
    构建并复用 SSLContext。

    优化点：
    不要在每个 IP 测试里都 ssl.create_default_context()。
    SSLContext 创建有额外成本，复用即可。
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def parse_http_status(status_line: bytes) -> int | None:
    """从 HTTP 状态行中解析状态码。"""
    try:
        parts = status_line.decode("ascii", errors="ignore").split()
        if len(parts) >= 2 and parts[0].startswith("HTTP/"):
            return int(parts[1])
    except Exception:
        return None

    return None


def is_good_http_status(status: int | None) -> bool:
    """
    判断 HTTP 状态是否说明 Cloudflare 边缘节点有正常响应。

    这里允许 2xx / 3xx / 4xx：
    - 2xx：正常成功
    - 3xx：跳转，也说明可用
    - 4xx：例如 403 / 404，通常也说明边缘节点、TLS、HTTP 都正常

    不接受 5xx：
    可能是源站或边缘侧错误，测速质量不稳定。
    """
    return status is not None and 200 <= status < 500


# -----------------------------------------------------------------------------
# 5. 第一阶段：TCP 快筛
# -----------------------------------------------------------------------------

async def tcp_probe_once(target: Target, *, timeout: float) -> TcpProbeResult | None:
    """
    TCP 快速探测。

    只做：
        TCP connect

    不做：
        TLS 握手
        HTTP 请求

    作用：
        快速淘汰不可达、明显超时、连接慢的 IP:PORT。
    """
    start = time.perf_counter()
    writer: asyncio.StreamWriter | None = None

    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target.ip, target.port),
            timeout=timeout,
        )

        latency_ms = (time.perf_counter() - start) * 1000

        return TcpProbeResult(
            ip=target.ip,
            port=target.port,
            latency_ms=latency_ms,
        )

    except Exception:
        return None

    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def stage1_tcp_prefilter(
    ips: list[str],
    ports: list[int],
    *,
    keep_per_port: int,
    concurrency: int,
    timeout: float,
    progress_every: int,
) -> dict[int, list[TcpProbeResult]]:
    """
    第一阶段主函数：TCP 快筛。

    输入：
        所有 IP 和所有端口。

    输出：
        每个端口保留 TCP 延迟最低的 keep_per_port 个候选。
    """
    targets = [Target(ip=ip, port=port) for ip in ips for port in ports]

    async def probe(target: Target) -> TcpProbeResult | None:
        return await tcp_probe_once(target, timeout=timeout)

    raw_results = await run_queue_workers(
        targets,
        probe,
        concurrency=concurrency,
        progress_every=progress_every,
        label="TCP",
    )

    grouped: dict[int, list[TcpProbeResult]] = defaultdict(list)

    for result in raw_results:
        grouped[result.port].append(result)

    best_by_port: dict[int, list[TcpProbeResult]] = {}

    for port in ports:
        items = grouped.get(port, [])
        best_by_port[port] = heapq.nsmallest(
            keep_per_port,
            items,
            key=lambda x: x.latency_ms,
        )

    return best_by_port


# -----------------------------------------------------------------------------
# 6. 第二阶段：TLS + HTTP 精测
# -----------------------------------------------------------------------------

async def http_probe_once(
    target: Target,
    *,
    ssl_ctx: ssl.SSLContext,
    sni: str,
    path: str,
    timeout: float,
) -> tuple[float, int] | None:
    """
    单次 TLS + HTTP 精测。

    连接目标：
        target.ip:target.port

    TLS SNI：
        sni

    HTTP Host：
        sni

    统计耗时范围：
        TCP connect + TLS handshake + HTTP request + 读到 HTTP 状态行

    返回：
        (latency_ms, http_status)
    """
    start = time.perf_counter()
    writer: asyncio.StreamWriter | None = None

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=target.ip,
                port=target.port,
                ssl=ssl_ctx,
                server_hostname=sni,
            ),
            timeout=timeout,
        )

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            f"User-Agent: best-ip-python/3.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        writer.write(request.encode("ascii"))
        await asyncio.wait_for(writer.drain(), timeout=timeout)

        # 只读 HTTP 状态行，不读完整响应体。
        # 读完整响应体会明显拖慢测速。
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        latency_ms = (time.perf_counter() - start) * 1000

        status = parse_http_status(status_line)

        if is_good_http_status(status):
            return latency_ms, status

        return None

    except Exception:
        return None

    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def http_probe_multi_sample(
    target: Target,
    *,
    ssl_ctx: ssl.SSLContext,
    sni: str,
    path: str,
    timeout: float,
    samples: int,
    sample_interval: float,
) -> HttpProbeResult | None:
    """
    对同一个 IP:PORT 做多次 TLS + HTTP 测试，取中位数。

    为什么取中位数而不是平均值？

    网络抖动经常会出现这样的数据：
        80ms, 82ms, 460ms

    平均值是 207ms，会被一次异常拉高。
    中位数是 82ms，更能代表常态表现。
    """
    latencies: list[float] = []
    status_codes: list[int] = []

    for i in range(samples):
        result = await http_probe_once(
            target,
            ssl_ctx=ssl_ctx,
            sni=sni,
            path=path,
            timeout=timeout,
        )

        if result is not None:
            latency_ms, status = result
            latencies.append(latency_ms)
            status_codes.append(status)

        if i != samples - 1 and sample_interval > 0:
            await asyncio.sleep(sample_interval)

    if not latencies:
        return None

    return HttpProbeResult(
        ip=target.ip,
        port=target.port,
        latency_ms=statistics.median(latencies),
        samples=tuple(latencies),
        status_codes=tuple(status_codes),
    )


async def stage2_http_refine(
    tcp_candidates: dict[int, list[TcpProbeResult]],
    ports: list[int],
    *,
    top_n: int,
    concurrency: int,
    timeout: float,
    samples: int,
    sample_interval: float,
    sni: str,
    path: str,
    progress_every: int,
) -> dict[int, list[HttpProbeResult]]:
    """
    第二阶段主函数：TLS + HTTP 精测。

    输入：
        TCP 快筛得到的候选。

    输出：
        每个端口延迟最低的 Top N。
    """
    targets = [
        Target(ip=item.ip, port=item.port)
        for port in ports
        for item in tcp_candidates.get(port, [])
    ]

    ssl_ctx = build_ssl_context()

    async def probe(target: Target) -> HttpProbeResult | None:
        return await http_probe_multi_sample(
            target,
            ssl_ctx=ssl_ctx,
            sni=sni,
            path=path,
            timeout=timeout,
            samples=samples,
            sample_interval=sample_interval,
        )

    raw_results = await run_queue_workers(
        targets,
        probe,
        concurrency=concurrency,
        progress_every=progress_every,
        label="HTTP",
    )

    grouped: dict[int, list[HttpProbeResult]] = defaultdict(list)

    for result in raw_results:
        grouped[result.port].append(result)

    final_by_port: dict[int, list[HttpProbeResult]] = {}

    for port in ports:
        items = grouped.get(port, [])
        final_by_port[port] = heapq.nsmallest(
            top_n,
            items,
            key=lambda x: x.latency_ms,
        )

    return final_by_port


# -----------------------------------------------------------------------------
# 7. 通用异步 worker 队列
# -----------------------------------------------------------------------------

async def run_queue_workers(
    targets: list[Target],
    worker_func: Callable[[Target], Awaitable[T | None]],
    *,
    concurrency: int,
    progress_every: int,
    label: str,
) -> list[T]:
    """
    通用异步任务队列。

    这是本脚本最值得学习的高级结构之一。

    为什么不用一次性 asyncio.gather(*所有任务)？

    如果有 10 万个任务：
        asyncio.gather(*tasks)

    会一次性创建 10 万个 Task，内存压力大，调度成本高。

    Queue + 固定数量 worker 的方式：
        只创建 concurrency 个 worker。
        worker 从队列中不断取任务处理。

    优点：
        - 全局并发可控
        - 内存稳定
        - 适合海量 IP:PORT 测试
    """
    if concurrency <= 0:
        raise ValueError("concurrency 必须大于 0")

    queue: asyncio.Queue[Target] = asyncio.Queue()

    for target in targets:
        queue.put_nowait(target)

    results: list[T] = []
    stats = QueueStats(total=len(targets))

    async def worker(worker_id: int) -> None:
        while True:
            try:
                target = queue.get_nowait()
            except asyncio.QueueEmpty:
                return

            try:
                result = await worker_func(target)

                stats.done += 1

                if result is None:
                    stats.failed += 1
                else:
                    stats.success += 1
                    results.append(result)

                if progress_every > 0 and stats.done % progress_every == 0:
                    print(
                        f"[{label}] "
                        f"{stats.done}/{stats.total} "
                        f"({stats.percent:.1f}%), "
                        f"success={stats.success}, "
                        f"failed={stats.failed}, "
                        f"queue={queue.qsize()}"
                    )

            finally:
                queue.task_done()

    workers = [
        asyncio.create_task(worker(i))
        for i in range(concurrency)
    ]

    await queue.join()

    # worker 正常会因为 QueueEmpty return。
    # 这里 cancel 是防御性写法，确保没有残留 worker。
    for task in workers:
        task.cancel()

    await asyncio.gather(*workers, return_exceptions=True)

    print(
        f"[{label}] done: total={stats.total}, "
        f"success={stats.success}, failed={stats.failed}"
    )

    return results


# -----------------------------------------------------------------------------
# 8. 总流程
# -----------------------------------------------------------------------------

async def best_ip_two_stage(
    ips: list[str],
    ports: list[int],
    *,
    tcp_keep_per_port: int,
    top_n: int,
    tcp_concurrency: int,
    http_concurrency: int,
    tcp_timeout: float,
    http_timeout: float,
    http_samples: int,
    sample_interval: float,
    sni: str,
    path: str,
    progress_every: int,
) -> dict[int, list[HttpProbeResult]]:
    """
    两阶段在线优选总入口。
    """
    print("===== Stage 1: TCP 快筛 =====")
    print(f"候选 IP 数量: {len(ips)}")
    print(f"端口列表: {','.join(map(str, ports))}")
    print(f"TCP 总任务数: {len(ips) * len(ports)}")
    print(f"TCP 并发: {tcp_concurrency}, TCP 超时: {tcp_timeout}s")
    print()

    tcp_candidates = await stage1_tcp_prefilter(
        ips=ips,
        ports=ports,
        keep_per_port=tcp_keep_per_port,
        concurrency=tcp_concurrency,
        timeout=tcp_timeout,
        progress_every=progress_every,
    )

    print("\nTCP 快筛保留数量：")
    for port in ports:
        print(f"  Port {port}: {len(tcp_candidates.get(port, []))}")

    print("\n===== Stage 2: TLS + HTTP 精测 =====")
    print(f"每端口最终保留: {top_n}")
    print(f"HTTP 并发: {http_concurrency}, HTTP 超时: {http_timeout}s")
    print(f"每个候选采样次数: {http_samples}")
    print(f"SNI / Host: {sni}")
    print(f"Path: {path}")
    print()

    final_results = await stage2_http_refine(
        tcp_candidates=tcp_candidates,
        ports=ports,
        top_n=top_n,
        concurrency=http_concurrency,
        timeout=http_timeout,
        samples=http_samples,
        sample_interval=sample_interval,
        sni=sni,
        path=path,
        progress_every=max(1, progress_every // 5),
    )

    return final_results


# -----------------------------------------------------------------------------
# 9. 输出
# -----------------------------------------------------------------------------

def format_results(
    results: dict[int, list[HttpProbeResult]],
    ports: list[int],
    *,
    debug: bool,
) -> str:
    """把结果格式化为文本。"""
    lines: list[str] = []

    for port in ports:
        lines.append(f"# Port {port}")

        items = results.get(port, [])

        if not items:
            lines.append("# 无可用结果")
            lines.append("")
            continue

        for item in items:
            if debug:
                lines.append(item.debug_line)
            else:
                lines.append(item.edgetunnel_line)

        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def save_results(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


# -----------------------------------------------------------------------------
# 10. CLI 参数
# -----------------------------------------------------------------------------

def parse_ports(text: str) -> list[int]:
    """解析 --ports 443,2053,2083 格式。"""
    ports: list[int] = []

    for part in text.split(","):
        part = part.strip()
        if not part:
            continue

        port = int(part)
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"非法端口: {port}")

        ports.append(port)

    if not ports:
        raise argparse.ArgumentTypeError("端口列表不能为空")

    return ports


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="在线优选 Cloudflare IP：TCP 快筛 + TLS/HTTP 精测",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    ip_group = parser.add_argument_group("IP 来源")
    ip_group.add_argument(
        "--count",
        type=int,
        default=2048,
        help="随机生成的候选 IP 数量",
    )
    ip_group.add_argument(
        "--ipv6",
        action="store_true",
        help="使用 Cloudflare IPv6 段，默认使用 IPv4",
    )
    ip_group.add_argument(
        "--input",
        type=str,
        default=None,
        help="从文件读取候选 IP；提供后不再随机生成",
    )

    probe_group = parser.add_argument_group("测试参数")
    probe_group.add_argument(
        "--ports",
        type=parse_ports,
        default=DEFAULT_PORTS,
        help="要测试的端口，逗号分隔",
    )
    probe_group.add_argument(
        "--sni",
        type=str,
        default="speed.cloudflare.com",
        help="TLS SNI 与 HTTP Host",
    )
    probe_group.add_argument(
        "--path",
        type=str,
        default="/cdn-cgi/trace",
        help="HTTP 测试路径",
    )
    probe_group.add_argument(
        "--tcp-timeout",
        type=float,
        default=0.8,
        help="TCP 快筛单目标超时秒数",
    )
    probe_group.add_argument(
        "--http-timeout",
        type=float,
        default=3.0,
        help="TLS/HTTP 精测单目标超时秒数",
    )
    probe_group.add_argument(
        "--samples",
        type=int,
        default=3,
        help="第二阶段每个目标采样次数",
    )
    probe_group.add_argument(
        "--sample-interval",
        type=float,
        default=0.05,
        help="同一目标多次采样之间的间隔秒数",
    )

    concurrency_group = parser.add_argument_group("并发与筛选")
    concurrency_group.add_argument(
        "--tcp-concurrency",
        type=int,
        default=512,
        help="TCP 快筛全局并发数",
    )
    concurrency_group.add_argument(
        "--http-concurrency",
        type=int,
        default=128,
        help="TLS/HTTP 精测全局并发数",
    )
    concurrency_group.add_argument(
        "--tcp-keep",
        type=int,
        default=128,
        help="第一阶段每个端口保留多少候选进入第二阶段",
    )
    concurrency_group.add_argument(
        "--top",
        type=int,
        default=16,
        help="最终每个端口输出前多少个结果",
    )

    output_group = parser.add_argument_group("输出")
    output_group.add_argument(
        "--output",
        type=str,
        default=None,
        help="保存结果到文件",
    )
    output_group.add_argument(
        "--debug",
        action="store_true",
        help="输出 samples 和 status 调试信息",
    )
    output_group.add_argument(
        "--progress-every",
        type=int,
        default=500,
        help="每完成多少任务打印一次进度；0 表示不打印中间进度",
    )
    output_group.add_argument(
        "--seed",
        type=int,
        default=None,
        help="随机种子，方便复现实验",
    )

    return parser


# -----------------------------------------------------------------------------
# 11. main
# -----------------------------------------------------------------------------

async def async_main(args: argparse.Namespace) -> int:
    if args.seed is not None:
        random.seed(args.seed)

    if args.input:
        ips = load_ips_from_file(args.input)
        if not ips:
            print(f"输入文件没有解析到有效 IP: {args.input}", file=sys.stderr)
            return 2
    else:
        cidrs = CF_IPV6_CIDRS if args.ipv6 else CF_IPV4_CIDRS
        ips = build_candidate_ips(cidrs, count=args.count)

    started = time.perf_counter()

    results = await best_ip_two_stage(
        ips=ips,
        ports=args.ports,
        tcp_keep_per_port=args.tcp_keep,
        top_n=args.top,
        tcp_concurrency=args.tcp_concurrency,
        http_concurrency=args.http_concurrency,
        tcp_timeout=args.tcp_timeout,
        http_timeout=args.http_timeout,
        http_samples=args.samples,
        sample_interval=args.sample_interval,
        sni=args.sni,
        path=args.path,
        progress_every=args.progress_every,
    )

    elapsed = time.perf_counter() - started

    text = format_results(results, args.ports, debug=args.debug)

    print("\n===== 最终优选结果 =====")
    print(text)
    print(f"总耗时: {elapsed:.1f}s")

    if args.output:
        save_results(args.output, text)
        print(f"结果已保存到: {args.output}")

    return 0


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.count <= 0:
        parser.error("--count 必须大于 0")
    if args.samples <= 0:
        parser.error("--samples 必须大于 0")
    if args.tcp_keep <= 0:
        parser.error("--tcp-keep 必须大于 0")
    if args.top <= 0:
        parser.error("--top 必须大于 0")

    try:
        code = asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\n用户中断", file=sys.stderr)
        code = 130

    raise SystemExit(code)


if __name__ == "__main__":
    main()
