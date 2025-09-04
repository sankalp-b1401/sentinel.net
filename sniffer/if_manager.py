# sniffer/if_manager.py
from __future__ import annotations
import sys
from tabulate import tabulate
from psutil import net_if_stats, net_if_addrs

try:
    # Windows
    from scapy.arch.windows import get_windows_if_list
    def _list_ifaces():
        return get_windows_if_list()
except Exception:
    # Linux/macOS fallback using psutil
    def _list_ifaces():
        out = []
        for name, addrs in net_if_addrs().items():
            ips = [a.address for a in addrs if getattr(a, "family", None) in (2, 23)]  # AF_INET/AF_INET6-ish
            macs = [a.address for a in addrs if str(getattr(a, "family", "")) == "AF_LINK"]
            out.append({
                "name": name,
                "description": name,
                "index": None,
                "ips": ips,
                "mac": macs[0] if macs else None,
            })
        return out

class InterfaceManager:
    def __init__(self) -> None:
        self._if_list = []
        self._if_stats = {}

    def refresh(self) -> None:
        try:
            self._if_list = _list_ifaces()
            self._if_stats = net_if_stats()
        except Exception as e:
            raise RuntimeError(f"Error retrieving interfaces: {e}")

    def usable(self) -> list[dict]:
        self.refresh()
        usable = []
        for iface in self._if_list:
            name = iface.get("name", "")
            if "Loopback" in (iface.get("description") or "") or name.lower().startswith("lo"):
                continue
            stats = self._if_stats.get(name)
            if not stats or not stats.isup:
                continue
            usable.append(iface)
        if not usable:
            raise RuntimeError("No usable network interfaces found.")
        return usable

    def display(self, interfaces: list[dict]) -> None:
        rows = []
        for idx, iface in enumerate(interfaces, start=1):
            name = iface.get("name", "NA")
            desc = iface.get("description", "NA")
            idx_sys = iface.get("index", "NA")
            ips = ", ".join(iface.get("ips") or []) or "NA"
            mac = iface.get("mac", "NA")
            status = "Up" if self._if_stats.get(name, None) and self._if_stats[name].isup else "Down"
            rows.append([idx, name, desc, idx_sys, status, ips, mac])
        print(tabulate(rows, headers=["Idx","Name","Description","SystemIdx","Status","IP(s)","MAC"], tablefmt="fancy_grid"))

    def select(self) -> dict:
        interfaces = self.usable()
        self.display(interfaces)
        while True:
            try:
                choice = int(input(f"\nSelect interface (1-{len(interfaces)}): "))
                if 1 <= choice <= len(interfaces):
                    return interfaces[choice - 1]
            except ValueError:
                pass
            print("Invalid selection. Try again.")

if __name__ == "__main__":
    try:
        iface = InterfaceManager().select()
        print("\n[ok] Selected:", iface.get("name"))
    except Exception as e:
        print(f"[err] {e}")
        sys.exit(1)
