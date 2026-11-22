# Source from your shell rc. Runs aurguard before upgrading AUR packages and
# stops if anything high-severity shows up; review it, then use plain paru.
#   paru-guarded -Sua --ignore opentabletdriver
paru-guarded() {
    aurguard check --diff || {
        echo "aurguard found something - review the output above before upgrading." >&2
        return 1
    }
    paru "$@"
}
