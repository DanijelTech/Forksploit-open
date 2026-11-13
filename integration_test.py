import glob
import multiprocessing
import os
import random
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "onchain_scripts"))
from chains import get_rpc_url, known_chains  # noqa: E402

TIMEOUT_BIN = "timeout" if os.name == "posix" else "gtimeout"

# How many tests/evm/* fixtures test_one() runs at once. The fuzzer itself
# now caps concolic (Z3) solvers campaign-wide at min(2, cores) -- see
# forksploit's own --help / max_concolic_threads(); it is no longer the
# historical "number of CPUs" default that let each worker try to claim
# every core. Because this harness runs OFFCHAIN_POOL_SIZE fuzzers as
# SEPARATE processes, the cap is shared, not multiplied: each worker is
# given its own share (max(1, cap // pool_size)) instead of the whole cap.
# That keeps the campaign within the same bound as the in-process --jobs
# path (per_job_concolic_threads in src/evm/multicore.rs).
OFFCHAIN_POOL_SIZE = min(6, multiprocessing.cpu_count())
OFFCHAIN_CONCOLIC_CAP = min(2, multiprocessing.cpu_count())
OFFCHAIN_CONCOLIC_THREADS = max(1, OFFCHAIN_CONCOLIC_CAP // OFFCHAIN_POOL_SIZE)

crashed_any = False


def _find_solc() -> str:
    """Whatever `solc` resolves to on PATH is NOT reliable for compiling
    this project's fixtures (most require 0.8.x and --base-path, which a
    quite-common system-package solc like 0.5.16 doesn't even recognize
    as a flag) -- use the same pinned version auto_pipeline.py's own
    _find_solc() does. Confirmed live: on a machine with an old system
    solc on PATH, EVERY single fixture's compile step was silently
    failing with "unrecognised option '--base-path'" (an error message
    that doesn't contain the literal substring "Error", so the check
    below never caught it either) before this fix -- every fixture that
    had no pre-committed .abi/.bin fell back to "nothing to fuzz".
    """
    pinned = Path.home() / ".svm" / "0.8.24" / "solc-0.8.24"
    return str(pinned) if pinned.exists() else "solc"


def read_onchain_tests():
    tests = ""
    with open("onchain_tests.txt", "r") as file:
        tests = file.read().strip()

    tests = tests.strip().split("\n")
    tests = [test.split("\t") for test in tests]
    return tests


def test_one(path):
    global crashed_any
    print(path)
    # cleanup
    os.system(f"rm -rf {path}/build")

    # compile with solc
    p = subprocess.run(
        " ".join(
            [
                _find_solc(),
                f"{path}/*.sol",
                "-o",
                f"{path}/",
                "--bin",
                "--abi",
                "--overwrite",
                "--base-path",
                ".",
                "--combined-json",
                "bin-runtime,srcmap-runtime",
            ]
        ),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Checking for the substring "Error" alone missed real compile
    # failures whose message doesn't happen to contain that word (e.g.
    # solc 0.5.x's "unrecognised option '--base-path'") -- a non-zero
    # exit code is the actual, reliable signal that nothing got (re)compiled.
    if p.returncode != 0 or b"Error" in p.stderr or b"Error" in p.stdout:
        print(f"Error compiling {path}: {p.stderr.decode('utf-8', errors='replace')}")
        crashed_any = True
        return

    # run fuzzer and check whether the stdout has string success.
    # 60s, not the original 30s: confirmed live that this machine's
    # cpufreq governor is "powersave" (cores observed ranging ~2.7-4.4GHz
    # at idle, not pinned to max) and sudo access to switch it to
    # "performance" wasn't available in this environment -- a fixed
    # WALL-CLOCK timeout against a fixed random seed means a slower
    # ramp-up or a momentary frequency dip directly costs real fuzzing
    # iterations, not just elapsed time. Doubling the budget absorbs that
    # variance without needing a system-wide power setting change.
    start_time = time.time()
    cmd = [
        TIMEOUT_BIN,
        "60s",
        "./target/release/forksploit",
        "evm",
        "-t",
        f"'{path}/*'",
        "-f",
        # Explicit even though "all" is now also the CLI's own default --
        # this test should keep exercising every detector even if the
        # default ever changes again. The "high_confidence" preset
        # (opt-in via --detectors high_confidence) deliberately leaves out
        # several real oracles (MathCalculate, StateComparison,
        # UninitializedMemory, UncheckedCall, CentralizationRisk,
        # CurveVirtualPrice, PriceFeedStaleness, TwapManipulation -- see
        # OracleType::from_strs in src/evm/mod.rs) to reduce noise on a
        # real target. Confirmed live: under that preset,
        # tests/evm/overflow, uninitialized_memory, unchecked_call,
        # curve_virtual_price, price_feed_staleness, and
        # twap_manipulation could never pass no matter how long they ran
        # -- their own oracle was simply never enabled.
        "-d",
        "all",
    ]
    # exit(0)

    if "concolic" in path:
        cmd.append(f"--concolic --concolic-caller --concolic-num-threads {OFFCHAIN_CONCOLIC_THREADS}")

    if "taint" in path:
        cmd.append("--sha3-bypass")

    print(" ".join(cmd))

    p = subprocess.run(
        " ".join(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
    )

    if b"Found vulnerabilities!" not in p.stdout:
        print("================ STDERR =================")
        print(p.stderr.decode("utf-8"))
        print("================ STDOUT =================")
        print(p.stdout.decode("utf-8"))
        print(f"=== Failed to fuzz {path}")
        if b"panicked" in p.stderr or b"panicked" in p.stdout:
            crashed_any = True
        return False, path
    else:
        print(f"=== Success: {path}, Finished in {time.time() - start_time}s")
        return True, path

    # clean up
    # os.system(f"rm -rf {path}/*.abi")
    # os.system(f"rm -rf {path}/*.bin")


def test_onchain(test):
    global crashed_any
    if len(test) != 4:
        print(f"=== Invalid test: {test}")
        crashed_any = True
        return

    # randomly sleep for 0 - 30s to avoid peak traffic
    time.sleep(60 * random.random())

    contract_addresses, block_number, chain, name = test[3], test[2], test[1], test[0]

    # Was a hardcoded ["eth", "bsc", "polygon"] list -- silently rejected
    # every other chain this project actually supports (confirmed real,
    # not hypothetical: ETC/Mordor, and the 10+ chains chains.py's own
    # DEFAULT_RPC gained this session). known_chains() is the single
    # authoritative list (src/evm/onchain/endpoints.rs's Chain enum, via
    # onchain_scripts/chains.py), so a chain added there is automatically
    # usable here too instead of needing a second hardcoded list kept in
    # sync by hand.
    if chain not in known_chains():
        print(f"=== Unsupported chain: {chain} (not in onchain_scripts/chains.py's known_chains())")
        crashed_any = True
        return

    # Was an unconditional requirement -- but -k/--onchain-etherscan-api-key
    # is genuinely optional at the Rust CLI level (a missing key just means
    # degraded/rate-limited ABI fetching, not a hard failure), and several
    # chains (ETC, Mordor, Vana, Story) have NO Etherscan coverage at all --
    # they route through Blockscout instead (is_blockscout_api() in
    # src/evm/onchain/endpoints.rs) and never needed one in the first place.
    # Use it if set, proceed without it otherwise, instead of treating
    # "no key" as a crash on every chain regardless of whether it needs one.
    etherscan_key = os.getenv(f"{chain.upper()}_ETHERSCAN_API_KEY")
    my_env = os.environ.copy()
    # Was os.getenv(...) directly, which is None (and crashes
    # subprocess.run's env= with a TypeError) for any chain without that
    # exact env var set -- fall back to chains.py's own real default RPC
    # for that chain instead of assuming the env var always exists.
    my_env["ETH_RPC_URL"] = os.getenv(f"{chain.upper()}_RPC_URL") or get_rpc_url(chain)
    my_env["RUST_BACKTRACE"] = "1"

    cmd = [
        TIMEOUT_BIN,
        # set timeout to 5m because it takes longer time to sync the chain
        "5m",
        "./target/release/forksploit",
        "evm",
        "-t",
        contract_addresses,
        "-c",
        chain,
        "-b",
        str(block_number),
        "-f",
        "--work-dir",
        f"w_{name}",
        # "--run-forever"
    ]
    if etherscan_key:
        cmd += ["--onchain-etherscan-api-key", etherscan_key]
    # Same reasoning as auto_pipeline.py's run_fuzzer(): ETC/Mordor need
    # --spec-id Shanghai or the DIFFICULTY opcode behaves wrong -- the
    # Rust binary only warns (non-fatal) if this is missing, so make sure
    # this test harness doesn't rely on noticing that warning either.
    if chain in ("etc", "mordor"):
        cmd += ["--spec-id", "Shanghai"]

    start_time = time.time()

    # try 3 times in case of rpc failure
    for i in range(3):
        p = subprocess.run(
            " ".join(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            env=my_env,
        )

        if b"Found vulnerabilities" in p.stdout:
            print(
                f"=== Success: Tested onchain for contracts: {name}, Finished in {time.time() - start_time}s"
            )
            open(f"res_{name}.txt", "w+").write(
                p.stderr.decode("utf-8")
                + " ".join(cmd)
                + "\n"
                + p.stdout.decode("utf-8")
            )
            return
        if b"panicked" in p.stderr or b"panicked" in p.stdout:
            crashed_any = True
            print("================ STDERR =================")
            print(p.stderr.decode("utf-8"))
            print("================ STDOUT =================")
            print(p.stdout.decode("utf-8"))
        time.sleep(30)

    print(f"=== Failed to test onchain for contracts: {name}")
    open(f"res_{name}.txt", "w+").write(
        p.stderr.decode("utf-8") + " ".join(cmd) + "\n" + p.stdout.decode("utf-8")
    )


def build_fuzzer():
    # build fuzzer
    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "--features",
            "cmp dataflow evm print_txn_corpus full_trace",
            "--no-default-features",
        ]
    )


def build_flash_loan_v2_fuzzer():
    # build fuzzer
    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "--features",
            "cmp dataflow evm print_txn_corpus full_trace force_cache",
            "--no-default-features",
        ]
    )


import multiprocessing
import sys

if __name__ == "__main__":
    actions = []

    if len(sys.argv) > 1:
        if sys.argv[1] == "onchain":
            actions.append("onchain")
        elif sys.argv[1] == "offchain":
            actions.append("offchain")
    else:
        actions = ["onchain", "offchain"]

    if "offchain" in actions:
        build_fuzzer()
        with multiprocessing.Pool(OFFCHAIN_POOL_SIZE) as p:
            results = p.map(test_one, glob.glob("./tests/evm/*", recursive=True))
        failed = [result for result in results if result and not result[0]]
        if failed:
            print("❌ Failed tests:")
            for f in failed:
                print(f[1])
            exit(1)

    if "onchain" in actions:
        build_flash_loan_v2_fuzzer()
        tests = read_onchain_tests()
        with multiprocessing.Pool(10) as p:
            p.map(test_onchain, tests)

    if crashed_any:
        exit(1)
