import argparse
import json
import os
import statistics
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Dict, Optional

from monotonic import monotonic
from detect_secrets.core.color import AnsiColor, colorize
from detect_secrets.core.usage import PluginOptions
from detect_secrets.util import get_root_directory


@dataclass
class BenchmarkConfig:
    filenames: List[str]
    plugins: List[str]
    pretty: bool
    timeout: float
    iterations: int
    baseline: Optional[Dict]


def parse_args() -> BenchmarkConfig:
    all_plugins = [info.classname for info in PluginOptions.all_plugins]

    parser = argparse.ArgumentParser(description="Run detect-secrets performance benchmarks.")
    parser.add_argument(
        "filenames",
        nargs=argparse.REMAINDER,
        help="Files or directories to scan.",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print output.")
    parser.add_argument(
        "--plugin",
        default=None,
        choices=all_plugins,
        action="append",
        help="Plugins to benchmark (default: all).",
    )
    parser.add_argument(
        "--harakiri",
        default=5.0,
        type=_positive(float),
        help="Timeout per execution (seconds).",
    )
    parser.add_argument(
        "-n",
        "--num-iterations",
        default=1,
        type=_positive(int),
        help="Number of iterations per benchmark.",
    )
    parser.add_argument(
        "--baseline",
        type=_valid_json_file,
        help="Baseline JSON to compare against.",
    )

    args = parser.parse_args()

    filenames = args.filenames or (
        args.baseline["filenames"] if args.baseline else [get_root_directory()]
    )
    plugins = args.plugin or all_plugins

    return BenchmarkConfig(
        filenames=filenames,
        plugins=plugins,
        pretty=args.pretty,
        timeout=args.harakiri,
        iterations=args.num_iterations,
        baseline=args.baseline,
    )


def _positive(type_):
    def wrapped(value):
        v = type_(value)
        if v <= 0:
            raise argparse.ArgumentTypeError(f"{value} must be a positive {type_.__name__}.")
        return v
    return wrapped


def _valid_json_file(path: str):
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"{path} must be a valid file.")
    with open(path) as f:
        return json.load(f)


def run_scan(filenames: List[str], timeout: float, flags: List[str]) -> Optional[float]:
    start = monotonic()
    try:
        subprocess.run(
            ["detect-secrets", "scan", *filenames, *flags],
            timeout=timeout,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return monotonic() - start
    except subprocess.TimeoutExpired:
        return None


def benchmark(config: BenchmarkConfig) -> Dict[str, Optional[float]]:
    disabled_flags = []
    plugin_flags = {}

    for info in PluginOptions.all_plugins:
        if info.classname in config.plugins:
            plugin_flags[info.disable_flag_text] = info.classname
        else:
            disabled_flags.append(info.disable_flag_text)

    results = {}

    # Benchmark all plugins enabled
    if len(config.plugins) == len(PluginOptions.all_plugins):
        results["all-plugins"] = _average_runs(
            config, flags=[]
        )

    # Benchmark each plugin disabled individually
    for idx, flag in enumerate(plugin_flags):
        ignore = list(plugin_flags.keys())
        ignore.pop(idx)

        plugin_name = plugin_flags[flag]
        results[plugin_name] = _average_runs(
            config,
            flags=ignore + disabled_flags,
        )

    return results


def _average_runs(config: BenchmarkConfig, flags: List[str]) -> Optional[float]:
    times = []
    for _ in range(config.iterations):
        t = run_scan(config.filenames, config.timeout, flags)
        times.append(t if t is not None else config.timeout)

    avg = statistics.mean(times)
    return None if avg == config.timeout else round(avg, 5)


def print_results(results: Dict[str, Optional[float]], config: BenchmarkConfig):
    baseline = config.baseline["timings"] if config.baseline else {}

    if not config.pretty and not baseline:
        print(json.dumps({"filenames": config.filenames, "timings": results}))
        return

    header_width = 60 if baseline else 45
    print("-" * header_width)

    if baseline:
        print(f"{'plugin':<25}{'time':>11}{'change':>22}")
    else:
        print(f"{'plugin':<25}{'time':>15}")

    print("-" * header_width)

    # Print all-plugins first if present
    if "all-plugins" in results:
        _print_line("All Plugins", results.pop("all-plugins"), baseline.get("all-plugins"), config.timeout)

    for plugin in sorted(results):
        _print_line(plugin, results[plugin], baseline.get(plugin), config.timeout)

    print("-" * header_width)


def _print_line(name: str, time: Optional[float], baseline: Optional[float], timeout: float):
    time_str = "Timeout exceeded!" if time is None else f"{time}s"

    if baseline is None:
        print(f"{name:<25}{time_str:>20}")
        return

    if time is None and baseline is None:
        diff = 0
    elif time is None:
        diff = round(timeout - baseline, 2)
    elif baseline is None:
        diff = round(timeout - time, 2)
    else:
        diff = round(baseline - time, 2)

    if diff > 0:
        diff_str = colorize(f"▲ {diff}", AnsiColor.LIGHT_GREEN)
    elif diff < 0:
        diff_str = colorize(f"▼ {diff}", AnsiColor.RED)
    else:
        diff_str = "-"

    print(f"{name:<25}{time_str:^20}{diff_str:>22}")


def main():
    config = parse_args()
    results = benchmark(config)
    print_results(results, config)


if __name__ == "__main__":
    main()
