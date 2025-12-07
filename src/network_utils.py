from scapy.all import conf, get_if_addr  # type: ignore

def get_interface_info(user_iface: str | None) -> tuple[str, str]:
    """
    Return (iface, ip).
    If user_iface is None, fall back to Scapy's default iface.
    """
    iface_obj = user_iface or conf.iface
    iface = str(iface_obj) 
    ip = get_if_addr(iface)
    return iface, ip
