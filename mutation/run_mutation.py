#!/usr/bin/env python3
"""Mutation campaign runner: apply each Gambit mutant, run the forge suite
under the light `mutation` profile, record which tests fail (= kill the
mutant). Resumable: already-recorded mutant ids in results.csv are skipped.

Outputs (all under mutation/):
  results.csv     — one row per mutant: set,id,file,description,status,
                    failed_count,duration_s,failed_tests(;-joined)
  failures/<set>-<id>.json — full failed-test detail per killed mutant
"""
import csv, json, os, shutil, subprocess, sys, time

REPO = "/home/agent/build/proof/specframe-proof-eas"
MUT = os.path.join(REPO, "mutation")
SETS = [
    ("eas", os.path.join(MUT, "gambit_out")),
    ("eip1271", os.path.join(MUT, "gambit_out_eip1271")),
]
RESULTS = os.path.join(MUT, "results.csv")
FAILDIR = os.path.join(MUT, "failures")
BACKUPDIR = os.path.join(MUT, "originals-backup")
PER_MUTANT_TIMEOUT = 1200  # s; a hung fuzz loop counts as killed (timeout)

ENV = dict(os.environ)
ENV["PATH"] = os.path.expanduser("~/.foundry/bin") + ":" + ENV.get("PATH", "")
ENV["FOUNDRY_PROFILE"] = "mutation"


def load_mutants():
    mutants = []
    for set_name, outdir in SETS:
        with open(os.path.join(outdir, "gambit_results.json")) as f:
            for m in json.load(f):
                mutants.append({
                    "set": set_name,
                    "id": m["id"],
                    "original": m["original"],
                    "description": m["description"],
                    "mutant_path": os.path.join(outdir, m["name"]),
                })
    return mutants


def backup_originals(mutants):
    os.makedirs(BACKUPDIR, exist_ok=True)
    for rel in sorted({m["original"] for m in mutants}):
        dst = os.path.join(BACKUPDIR, rel.replace("/", "__"))
        if not os.path.exists(dst):
            shutil.copy2(os.path.join(REPO, rel), dst)


def restore_originals(mutants):
    for rel in sorted({m["original"] for m in mutants}):
        src = os.path.join(BACKUPDIR, rel.replace("/", "__"))
        shutil.copy2(src, os.path.join(REPO, rel))


def parse_failures(stdout):
    """forge test --json => {suite: {test_results: {name: {status,...}}}}"""
    failed = []
    data = json.loads(stdout)
    for suite, sres in data.items():
        for tname, tres in sres.get("test_results", {}).items():
            if tres.get("status") == "Failure":
                short_suite = suite.split(":")[-1]
                failed.append({
                    "suite": short_suite,
                    "test": tname,
                    "reason": (tres.get("reason") or "")[:300],
                })
    return failed


def run_one(m):
    target = os.path.join(REPO, m["original"])
    shutil.copy2(m["mutant_path"], target)
    t0 = time.time()
    try:
        p = subprocess.run(
            ["forge", "test", "--json"], cwd=REPO, env=ENV,
            capture_output=True, text=True, timeout=PER_MUTANT_TIMEOUT)
        dur = round(time.time() - t0, 1)
        try:
            failed = parse_failures(p.stdout)
        except (json.JSONDecodeError, AttributeError):
            # Non-JSON output with rc!=0 => build/runtime error. Gambit
            # validated compilation, so treat as killed-by-error but flag it.
            return ("error" if p.returncode != 0 else "parse-error"), [], dur, p.stdout[-2000:] + p.stderr[-2000:]
        if failed:
            return "killed", failed, dur, None
        if p.returncode != 0:
            return "error", [], dur, p.stderr[-2000:]
        return "survived", [], dur, None
    except subprocess.TimeoutExpired:
        return "timeout", [], round(time.time() - t0, 1), None
    finally:
        restore_originals([m])


def main():
    mutants = load_mutants()
    backup_originals(mutants)
    # A prior run may have died mid-mutant, leaving a mutated file in place.
    restore_originals(mutants)
    os.makedirs(FAILDIR, exist_ok=True)

    done = set()
    if os.path.exists(RESULTS):
        with open(RESULTS) as f:
            for row in csv.reader(f):
                if row and row[0] != "set":
                    done.add((row[0], row[1]))
    else:
        with open(RESULTS, "w", newline="") as f:
            csv.writer(f).writerow([
                "set", "id", "file", "description", "status",
                "failed_count", "duration_s", "failed_tests"])

    todo = [m for m in mutants if (m["set"], m["id"]) not in done]
    print(f"[runner] {len(mutants)} mutants total, {len(done)} done, "
          f"{len(todo)} to run", flush=True)

    for i, m in enumerate(todo, 1):
        status, failed, dur, errtail = run_one(m)
        names = ";".join(f"{x['suite']}.{x['test']}" for x in failed)
        with open(RESULTS, "a", newline="") as f:
            csv.writer(f).writerow([
                m["set"], m["id"], m["original"], m["description"],
                status, len(failed), dur, names])
        if failed or errtail:
            with open(os.path.join(FAILDIR, f"{m['set']}-{m['id']}.json"), "w") as f:
                json.dump({"mutant": m, "status": status,
                           "failed": failed, "errtail": errtail}, f, indent=1)
        print(f"[runner] {i}/{len(todo)} {m['set']}-{m['id']} "
              f"{m['description']} -> {status} ({len(failed)} fails, {dur}s)",
              flush=True)

    restore_originals(mutants)
    print("[runner] campaign complete", flush=True)


if __name__ == "__main__":
    main()
