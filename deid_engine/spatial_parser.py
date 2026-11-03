"""
Stage 1: Spatial PDF Pre-Processor.
Handles character-level extraction, faux-bold deduplication, baseline Y-band clustering,
column-gap segmentation, and 1-to-1 character bounding-box mapping.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple
import pymupdf


def is_cjk_char(ch: str) -> bool:
    """Return True if character is in CJK Unified Ideographs or fullwidth punctuation."""
    if not ch:
        return False
    cp = ord(ch[0])
    return (
        0x4E00 <= cp <= 0x9FFF
        or 0x3400 <= cp <= 0x4DBF
        or 0xF900 <= cp <= 0xFAFF
        or 0x3000 <= cp <= 0x303F
        or 0xFF00 <= cp <= 0xFFEF
    )


@dataclass
class CharInfo:
    c: str
    bbox: Tuple[float, float, float, float]
    origin: Tuple[float, float]
    size: float
    color: int
    font: str
    page_num: int

    @property
    def is_cjk(self) -> bool:
        return is_cjk_char(self.c)


@dataclass
class OriginalSpanRecord:
    text: str
    bbox: List[float]
    origin: List[float]
    size: float
    color_int: int
    font: str
    is_cjk: bool


@dataclass
class LineSegment:
    page_num: int
    baseline_y: float
    text: str
    char_map: List[Optional[CharInfo]]  # Same length as `text`; None for synthetic spaces
    bbox: Tuple[float, float, float, float]

    def substring_bbox(self, start: int, end: int) -> Optional[Tuple[float, float, float, float]]:
        """Compute exact tight bounding box for text[start:end]."""
        chars = [c for c in self.char_map[start:end] if c is not None]
        if not chars:
            return None
        x0 = min(c.bbox[0] for c in chars)
        y0 = min(c.bbox[1] for c in chars)
        x1 = max(c.bbox[2] for c in chars)
        y1 = max(c.bbox[3] for c in chars)
        return (x0, y0, x1, y1)

    def substring_style(self, start: int, end: int) -> Tuple[Tuple[float, float], float, int, str]:
        """Return (origin, fontsize, color_int, font) of the first valid character in text[start:end]."""
        chars = [c for c in self.char_map[start:end] if c is not None]
        if not chars:
            return ((self.bbox[0], self.baseline_y), 9.0, 0, "helv")
        first = chars[0]
        # Prefer the largest font size among the matched spans so CJK/Latin mixed lines match visually
        max_size = max(c.size for c in chars)
        return (first.origin, max_size, first.color, first.font)

    def substring_original_spans(self, start: int, end: int) -> List[OriginalSpanRecord]:
        """
        Group contiguous characters in text[start:end] into OriginalSpanRecords
        for lossless reversal (preserving separate CJK vs Latin origins and sizes).
        """
        records: List[OriginalSpanRecord] = []
        cur_chars: List[CharInfo] = []
        cur_text: List[str] = []

        def flush():
            if not cur_chars:
                return
            x0 = min(c.bbox[0] for c in cur_chars)
            y0 = min(c.bbox[1] for c in cur_chars)
            x1 = max(c.bbox[2] for c in cur_chars)
            y1 = max(c.bbox[3] for c in cur_chars)
            records.append(
                OriginalSpanRecord(
                    text="".join(cur_text),
                    bbox=[round(x0, 3), round(y0, 3), round(x1, 3), round(y1, 3)],
                    origin=[round(cur_chars[0].origin[0], 3), round(cur_chars[0].origin[1], 3)],
                    size=round(cur_chars[0].size, 2),
                    color_int=cur_chars[0].color,
                    font=cur_chars[0].font,
                    is_cjk=any(c.is_cjk for c in cur_chars),
                )
            )

        for idx in range(start, min(end, len(self.text))):
            ch_info = self.char_map[idx]
            ch_str = self.text[idx]
            if ch_info is None:
                if cur_chars:
                    cur_text.append(" ")
                continue
            if not cur_chars:
                cur_chars.append(ch_info)
                cur_text.append(ch_str)
            else:
                prev = cur_chars[-1]
                # Split span record if script (CJK vs Latin) changes or large gap occurs
                gap = ch_info.bbox[0] - prev.bbox[2]
                if (
                    ch_info.is_cjk != prev.is_cjk
                    or abs(ch_info.size - prev.size) > 1.2
                    or ch_info.color != prev.color
                    or gap > max(8.0, prev.size * 0.9)
                ):
                    flush()
                    cur_chars = [ch_info]
                    cur_text = [ch_str]
                else:
                    cur_chars.append(ch_info)
                    cur_text.append(ch_str)
        flush()
        return records


@dataclass
class PageLayout:
    page_num: int
    width: float
    height: float
    segments: List[LineSegment] = field(default_factory=list)


def parse_page_layout(page: pymupdf.Page, page_num: int) -> PageLayout:
    """
    Extract and reconstruct spatial LineSegments from a PDF page.
    1. Extracts horizontal characters via rawdict.
    2. Deduplicates faux-bold overlapping identical characters.
    3. Groups characters into horizontal lines by baseline `origin[1]`.
    4. Splits lines into column segments by horizontal gaps while preserving CJK justified labels.
    """
    raw = page.get_text("rawdict")
    rect = page.rect
    chars: List[CharInfo] = []

    for block in raw.get("blocks", []):
        for line in block.get("lines", []):
            dir_x, _ = line.get("dir", (1.0, 0.0))
            if abs(dir_x) < 0.5:
                # Skip vertically rotated decorative sidebar labels (e.g. vertical PATIENT/PHYSICIAN)
                continue
            for span in line.get("spans", []):
                size = float(span.get("size", 9.0))
                color = int(span.get("color", 0))
                font = str(span.get("font", "helv"))
                for ch in span.get("chars", []):
                    c = ch.get("c", "")
                    if not c or c.isspace() or c == "\xa0":
                        continue
                    bbox = tuple(float(v) for v in ch["bbox"])
                    origin = tuple(float(v) for v in ch.get("origin", (bbox[0], bbox[3])))
                    chars.append(
                        CharInfo(
                            c=c,
                            bbox=bbox,
                            origin=origin,
                            size=size,
                            color=color,
                            font=font,
                            page_num=page_num,
                        )
                    )

    if not chars:
        return PageLayout(page_num=page_num, width=rect.width, height=rect.height, segments=[])

    # Step 1: Cluster by baseline Y (tolerance = 2.2pt)
    lines: List[dict] = []
    for ch in chars:
        placed = False
        for ln in lines:
            if abs(ln["y"] - ch.origin[1]) <= 2.2:
                ln["chars"].append(ch)
                # Update running mean baseline_y
                placed = True
                break
        if not placed:
            lines.append({"y": ch.origin[1], "chars": [ch]})

    lines.sort(key=lambda l: l["y"])

    all_segments: List[LineSegment] = []

    for ln in lines:
        line_chars: List[CharInfo] = ln["chars"]
        line_chars.sort(key=lambda c: c.bbox[0])

        # Step 2: Deduplicate faux-bold overlapping identical characters on the same line (offset ~0.1-0.4pt)
        dedup: List[CharInfo] = []
        for ch in line_chars:
            if dedup:
                prev = dedup[-1]
                dup_tol = min(0.65, ch.size * 0.09)
                if (
                    prev.c == ch.c
                    and abs(prev.origin[0] - ch.origin[0]) < dup_tol
                    and abs(prev.origin[1] - ch.origin[1]) < 1.2
                ):
                    continue
            dedup.append(ch)

        if not dedup:
            continue

        # Step 3: Segment line by column gaps
        # Check if line has a CJK colon '：' near the left to avoid splitting justified CJK labels like '醫   師：'
        colon_x = None
        for ch in dedup:
            if ch.c in ("：", ":") and ch.bbox[0] < 220:
                colon_x = ch.bbox[2]
                break

        raw_segs: List[List[CharInfo]] = []
        cur_seg: List[CharInfo] = [dedup[0]]

        for ch in dedup[1:]:
            prev = cur_seg[-1]
            gap = ch.bbox[0] - prev.bbox[2]
            col_thresh = max(13.5, prev.size * 1.45)

            # Do not split justified CJK characters that precede a colon on the same label
            is_justified_cjk_label = (
                colon_x is not None
                and ch.bbox[2] <= colon_x + 2.0
                and prev.is_cjk
                and (ch.is_cjk or ch.c in ("：", ":"))
                and gap < 50.0
            )

            if gap > col_thresh and not is_justified_cjk_label:
                raw_segs.append(cur_seg)
                cur_seg = [ch]
            else:
                cur_seg.append(ch)
        raw_segs.append(cur_seg)

        # Step 4: Build LineSegment with 1-to-1 char_map
        for seg_chars in raw_segs:
            text_parts: List[str] = [seg_chars[0].c]
            char_map: List[Optional[CharInfo]] = [seg_chars[0]]

            for c1, c2 in zip(seg_chars, seg_chars[1:]):
                gap = c2.bbox[0] - c1.bbox[2]
                # Insert a space if visual gap exceeds threshold
                space_thresh = max(0.75, min(c1.size, c2.size) * 0.15)
                if gap > space_thresh and not (c1.is_cjk and c2.is_cjk and gap < c1.size * 0.8):
                    text_parts.append(" ")
                    char_map.append(None)
                text_parts.append(c2.c)
                char_map.append(c2)

            seg_text = "".join(text_parts)
            x0 = min(c.bbox[0] for c in seg_chars)
            y0 = min(c.bbox[1] for c in seg_chars)
            x1 = max(c.bbox[2] for c in seg_chars)
            y1 = max(c.bbox[3] for c in seg_chars)

            all_segments.append(
                LineSegment(
                    page_num=page_num,
                    baseline_y=ln["y"],
                    text=seg_text,
                    char_map=char_map,
                    bbox=(x0, y0, x1, y1),
                )
            )

    return PageLayout(page_num=page_num, width=rect.width, height=rect.height, segments=all_segments)
