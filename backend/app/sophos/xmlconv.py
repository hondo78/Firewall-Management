"""Umwandlung Sophos-XML ⇄ JSON-Dicts.

Regeln (verlustfrei für die von der XML-API bzw. in Entities.xml verwendeten Strukturen):
- Element nur mit Text → str
- Element mit Kindern → dict; wiederholte Tags → Liste
- „Listen-Container“ (Name endet auf s/List, alle Kinder gleicher Tag) → {Tag: [ … ]}, auch bei nur einem Kind,
  damit z. B. SourceZones immer {"Zone": [...]} ist
- Attribute (transactionid) werden verworfen
"""
import io
import tarfile
import xml.etree.ElementTree as ET

# Schreib-Anweisungen für Regeln – nicht Teil des gespeicherten Objekts, sondern pro Operation angegeben
POSITION_KEYS = ("Position", "After", "Before")


def _is_list_container(tag: str, children: list[ET.Element]) -> bool:
    if not children:
        return False
    first = children[0].tag
    return (tag.endswith("s") or tag.endswith("List")) and all(c.tag == first for c in children)


def element_to_value(el: ET.Element):
    children = list(el)
    if not children:
        return (el.text or "").strip()
    if _is_list_container(el.tag, children):
        return {children[0].tag: [element_to_value(c) for c in children]}
    counts: dict[str, int] = {}
    for c in children:
        counts[c.tag] = counts.get(c.tag, 0) + 1
    out: dict = {}
    for c in children:
        v = element_to_value(c)
        if counts[c.tag] > 1:
            out.setdefault(c.tag, []).append(v)
        else:
            out[c.tag] = v
    return out


def value_to_element(tag: str, value) -> ET.Element:
    el = ET.Element(tag)
    _fill(el, value)
    return el


def _fill(el: ET.Element, value) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, list):
                for item in v:
                    el.append(value_to_element(k, item))
            else:
                el.append(value_to_element(k, v))
    elif value is None:
        return
    else:
        el.text = str(value)


def to_xml(tag: str, value, *, transactionid: bool = False, pretty: bool = True) -> str:
    el = value_to_element(tag, value)
    if transactionid:
        el.set("transactionid", "")
    if pretty:
        ET.indent(el, "  ")
    return ET.tostring(el, encoding="unicode")


def strip_position(data: dict) -> dict:
    return {k: v for k, v in data.items() if k not in POSITION_KEYS}


def position_fields(position: dict | None) -> dict:
    """{"type": "top|bottom|after|before", "ref": "Regelname"} → XML-Felder für FirewallRule."""
    if not position:
        return {}
    kind = (position.get("type") or "bottom").lower()
    if kind in ("after", "before") and position.get("ref"):
        tag = "After" if kind == "after" else "Before"
        return {"Position": tag, tag: {"Name": position["ref"]}}
    return {"Position": "Top" if kind == "top" else "Bottom"}


def with_position(data: dict, position: dict | None) -> dict:
    """Position direkt hinter Name/Description/IPFamily/Status einfügen (Reihenfolge wie im Sophos-Schema)."""
    pos = position_fields(position)
    if not pos:
        return data
    out: dict = {}
    inserted = False
    for k, v in data.items():
        if not inserted and k not in ("Name", "Description", "IPFamily", "Status"):
            out.update(pos)
            inserted = True
        out[k] = v
    if not inserted:
        out.update(pos)
    return out


def parse_objects(root: ET.Element, entities: set[str] | None = None) -> tuple[dict[str, list[dict]], str]:
    """Kinder eines <Configuration>/<Response>-Elements → {entity: [obj, …]} in Dokumentreihenfolge."""
    out: dict[str, list[dict]] = {}
    for child in root:
        if entities is not None and child.tag not in entities:
            continue
        value = element_to_value(child)
        if not isinstance(value, dict) or "Name" not in value:
            continue
        out.setdefault(child.tag, []).append(strip_position(value))
    return out, root.get("APIVersion", "")


def parse_entities_xml(data: bytes, entities: set[str] | None = None) -> tuple[dict[str, list[dict]], str]:
    return parse_objects(ET.fromstring(data), entities)


def build_entities_xml(objects: list[tuple[str, dict]], api_version: str = "") -> bytes:
    root = ET.Element("Configuration")
    if api_version:
        root.set("APIVersion", api_version)
    root.set("IPS_CAT_VER", "1")
    for tag, data in objects:
        el = value_to_element(tag, data)
        el.set("transactionid", "")
        root.append(el)
    ET.indent(root, "  ")
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8")


def read_tar_entities(archive: bytes) -> bytes:
    """Entities.xml aus dem Export-Archiv (.tar, ggf. gzip) lesen."""
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.split("/")[-1] == "Entities.xml":
                f = tar.extractfile(member)
                if f:
                    return f.read()
    raise ValueError("Archiv enthält keine Entities.xml")


def build_tar(entities_xml: bytes) -> bytes:
    """Import-Archiv: .tar mit Entities.xml (Dateiname darf nicht geändert werden)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("Entities.xml")
        info.size = len(entities_xml)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(entities_xml))
    return buf.getvalue()
