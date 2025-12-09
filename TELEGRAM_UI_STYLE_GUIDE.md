# Zaply - Telegram-Perfect UI Implementation
**Status:** ✅ COMPLETE & PRODUCTION READY  
**Last Updated:** December 9, 2025

---

## 🎨 TELEGRAM UI STYLE GUIDE

This document details the exact Telegram-style UI implementation in Zaply with perfect color matching, spacing, and interactions.

### Color Palette (Telegram Official Colors)
```
Primary Color:         #0088CC  (Telegram Blue - used for accents, badges, check marks)
Light Blue:            #E7F5FF  (Sky blue for hover states and secondary backgrounds)
Darker Blue:           #0077B5  (Darker shade for hover/pressed states)
Message Sent BG:       #EEFFDE  (Light green for outgoing messages)
Message Received BG:   #FFFFFF  (White for incoming messages)
Chat Selected:         #F0F2F5  (Light gray for selected chat item)
Text Primary:          #000000  (Black for main text)
Text Secondary:        #65686B  (Gray for subtitles)
Text Tertiary:         #999999  (Light gray for hints)
Divider:              #E9EDEF  (Light gray for separators)
Success:              #31A24C  (Green for success states)
Error:                #E53935  (Red for errors)
Background Primary:    #FFFFFF  (White main background)
Background Secondary:  #DFEAEF  (Light blue for chat background)
```

---

## 📐 SPACING & SIZING

### Standard Spacing Values
```python
from theme import SPACING

SPACING = {
    "xs": 2,      # Extra small gaps
    "sm": 4,      # Small gaps
    "md": 8,      # Medium gaps
    "lg": 12,     # Large gaps
    "xl": 16,     # Extra large gaps
    "2xl": 20,    # 2X large
    "3xl": 24,    # 3X large
    "4xl": 28,    # 4X large
}
```

### Font Sizes
```python
FONT_SIZES = {
    "xs": 10,     # Extra small text
    "sm": 12,     # Small text (subtitles)
    "base": 14,   # Base text (most common)
    "lg": 16,     # Large text (headers)
    "xl": 18,     # Extra large (title)
    "2xl": 20,    # 2X large
    "3xl": 24,    # 3X large (large headers)
}
```

### Border Radius
```python
RADIUS = {
    "sm": 4,      # Small radius
    "md": 8,      # Medium radius
    "lg": 12,     # Large radius
    "xl": 16,     # Extra large
    "2xl": 20,    # Full circle for avatars
    "full": 24,   # Full rounded (pill shape)
}
```

---

## 🗨️ MESSAGE BUBBLES

### Sent Messages (Right Aligned)
```
┌──────────────────────────────┐
│ Hello, how are you doing?    │  ✓✓
│ 10:30 AM                     │
└──────────────────────────────┘
  └─ 4px tail on bottom-right
```

**Properties:**
- Background: `#EEFFDE` (light green)
- Text Color: `#000000`
- Border Radius: `18px` (top-left, top-right, bottom-left), `4px` (bottom-right with tail effect)
- Padding: `14px horizontal × 8px vertical`
- Max Width: `360px` (70% of screen on mobile)
- Shadow: `blur 3px, spread 0, opacity 15%`
- Alignment: Right (80px margin from right edge)

**Time & Status:**
- Font Size: `11px`
- Color: `rgba(0, 0, 0, 0.6)`
- Check Mark Icon: `#0088CC` (blue color)
  - Single ✓: Sent
  - Double ✓✓: Delivered
  - Blue ✓✓: Read

### Received Messages (Left Aligned)
```
┌──────────────────────────────┐
│ I'm doing great! How about   │
│ you?                         │
│ 10:31 AM                     │
└──────────────────────────────┘
└─ 4px tail on bottom-left
```

**Properties:**
- Background: `#FFFFFF` (white)
- Text Color: `#000000`
- Border: `1px solid #E9EDEF`
- Border Radius: `4px` (bottom-left with tail), `18px` (others)
- Padding: `14px horizontal × 8px vertical`
- Max Width: `360px`
- Shadow: `blur 2px, spread 0, opacity 10%`
- Alignment: Left (8px margin from left edge)

### Sender Name (Group Chats)
- Only shown for received messages in group chats
- Font Size: `12px`
- Font Weight: `Bold (600)`
- Color: `#0088CC` (light blue)
- Margin Bottom: `4px` (between name and message)

### File Messages
```
📎 document.pdf
   Download
```

- Emoji Icon: `24px` size
- Filename: `14px` bold text
- "Download" link: `12px`, `#0088CC` color, underlined
- Container: Light background with icon circle (`40px × 40px`)

---

## 📱 CHAT LIST ITEMS

### Chat Item Structure
```
┌────────────────────────────────────────┐
│ [Avatar]  Chat Name          12:30 PM  │  
│ (56×56)   Last message prev...  (2)    │
└────────────────────────────────────────┘
  └─ 72px height, 8px vertical spacing
```

**Container Properties:**
- Height: `72px` (fixed)
- Padding: `8px horizontal × 4px vertical`
- Border Radius: `12px`
- Hover Background: `#F0F2F5` (light gray)
- Padding Interior: `12px`

### Avatar Component
- Size: `56px × 56px` circle
- Border Radius: `28px` (circular)
- Shadow: `blur 2px, spread 0, opacity 12%`
- Colors by Type:
  - Private Chat: `#0088CC` (light blue)
  - Group Chat: `#7C3AED` (purple)
  - Channel: `#EC4899` (pink)
- Content: First letter (bold, white) or Icon (white)

### Chat Info Row
**Left Column (Chat Name + Last Message):**
- Chat Name: `16px`, `bold (600)` if unread, `500` if read
- Color: `#000000` (black)
- Last Message: `14px`, `#65686B` (gray), ellipsis if too long
- Spacing Between: `4px`

**Right Column (Timestamp + Badge):**
- Timestamp: `13px`, `#65686B` (gray)
- Format: Relative time (e.g., "2m ago", "Yesterday")
- Unread Badge: 
  - Background: `#0088CC` (light blue)
  - Size: `20px × 20px` circle
  - Border Radius: `10px`
  - Text: `11px`, bold, white, centered
  - Count: "1" to "99" or "99+"

### Search Bar (Top)
```
🔍 Search...
```
- Height: `40px`
- Border Radius: `20px` (pill shape)
- Background: `#E7F5FF` (light blue)
- Icon: `#0088CC`
- Font: `14px` gray placeholder
- Padding: `0px 15px` (left/right)

---

## 💬 MESSAGE INPUT AREA

### Input Composer
```
┌─────────────────────────────────────────────────┐
│ [📎] [Message text input        ] [😊] [↗️]   │
└─────────────────────────────────────────────────┘
```

**Container:**
- Height: Auto (1-5 lines, expandable)
- Border Radius: `22px` (pill shape)
- Background: `#FFFFFF` (white)
- Border: `1px solid #E9EDEF`
- Shadow: `blur 1px, opacity 8%`
- Padding: `8px 12px` (internal)
- Margin: `8px 8px` (external)

### Input Field
- Border: None
- Multiline: Yes (min 1 line, max 5 lines)
- Font Size: `15px`
- Color: `#000000`
- Placeholder Color: `#999999`
- Placeholder Text: "Message..."
- Padding: `8px 12px`

### Action Buttons
**Attach Button [📎]**
- Icon: `ATTACH_FILE`
- Color: `#0088CC`
- Size: `26px`
- Hover Background: `#E7F5FF`
- Padding: `0px`
- Tooltip: "Attach"

**Emoji Button [😊]**
- Icon: `EMOJI_EMOTIONS_OUTLINED`
- Color: `#0088CC`
- Size: `26px`
- Hover Background: `#E7F5FF`
- Padding: `0px`
- Tooltip: "Emoji"

**Send Button [↗️]**
- Icon: `SEND`
- Color: `#FFFFFF` (white)
- Background: `#0088CC`
- Size: `28px icon`
- Shape: Circle (`28px × 28px`)
- Hover Background: `#0077B5` (darker blue)
- Border Radius: `14px` (circle)
- Tooltip: "Send"

---

## 📋 APP BAR

### Top Navigation Bar
```
[←] [Z] Chat Name         [🔔] [⋯]
    [56×56]   online
```

**Properties:**
- Height: `56px` (standard Material Design)
- Background: `#FFFFFF` (white)
- Elevation: `0` (flat design, no shadow)
- Padding: `8px 16px`

### Back Button
- Icon: `ARROW_BACK`
- Color: `#000000`
- Size: `24px`
- Padding: `8px`
- Width: `40px` (total)

### Chat Avatar (Center)
- Size: `42px × 42px` circle
- Background: `#0088CC`
- Icon/Letter: White color
- Margin Right: `10px`

### Chat Info (Center)
- Title: Chat Name
  - Font Size: `16px`
  - Font Weight: `Bold (600)`
  - Color: `#000000`
- Subtitle: Status
  - Font Size: `12px`
  - Color: `#0088CC` if online, `#65686B` if offline
  - Text: "online", "2h ago", "cloud storage", etc.
- Container: Column with 0 spacing

### Action Icons (Right)
**Connection Status Icon:**
- Wifi (Connected): `#0088CC`
- Sync (Connecting): `#FF9800` (orange)
- Wifi Off (Disconnected): `#F44336` (red)
- Size: `20px`
- Tooltip: "Connection: [status]"

**Call Button:**
- Icon: `CALL`
- Color: `#000000`
- Size: `24px`
- Tooltip: "Call"
- Padding: `8px`

**More Menu:**
- Icon: `MORE_VERT`
- Color: `#000000`
- Size: `24px`
- Menu Items:
  - 🔍 Search
  - 🔇 Mute
  - 🗑️ Clear history
  - 🔄 Reconnect

---

## 📅 DATE SEPARATORS

### Design
```
         December 8
```

- Text: Full date format (e.g., "December 8", "Yesterday")
- Font Size: `13px`
- Font Weight: `500`
- Color: `#65686B` (gray)
- Text Align: Center
- Background: Transparent or light gray
- Padding: `8px`
- Margin: `8px` vertical
- Line Through: Optional (thin gray line on each side)
- Opacity: `0.6`

**When to Show:**
- Between messages from different calendar days
- First message in conversation
- After gap > 10 minutes (optional)

---

## 🌙 DARK MODE

When `dark_mode=True`, all colors switch to dark variants:

```python
DARK_COLORS = {
    "accent": "#0088CC",           # Same blue
    "bg_primary": "#0F0F0F",       # Near black
    "bg_secondary": "#1A1A1A",     # Dark gray
    "text_primary": "#FFFFFF",     # White
    "text_secondary": "#AAAAAA",   # Light gray
    "message_sent": "#2B5278",     # Dark blue-green
    "message_received": "#1E1E1E", # Dark gray
    "border": "#2A2A2A",           # Dark border
    # ... other dark colors
}
```

### Dark Mode Message Bubbles
- **Sent:** `#2B5278` (dark blue-green)
- **Received:** `#1E1E1E` (dark gray)
- **Text:** `#FFFFFF` (white)
- **Timestamp:** `rgba(255, 255, 255, 0.6)`

---

## 🎨 EMOJI PICKER

### Layout
```
┌─────────────────────────────┐
│ Emojis          [×]         │
├─────────────────────────────┤
│ [⭐] [😀] [👋] [🐶] ...     │ Tabs (8px each)
├─────────────────────────────┤
│ 😀 😂 🤣 😃 😄 😁 ...      │
│ 😆 😅 🤭 🤨 😐 😑 ...      │
│ ... (8 columns, 100 emojis) │
├─────────────────────────────┤
└─────────────────────────────┘
```

**Emoji Grid:**
- Columns: `8 per row`
- Icon Size: `22px`
- Tap Area: `45px × 45px`
- Spacing: `2px`
- Max Display: `100 emojis per category`

**Tabs:**
- Tab Height: `40px`
- Indicator Color: `#0088CC`
- Text Size: `14px`
- Active Weight: `Bold (600)`

**Dialog:**
- Width: `350px`
- Height: `350px`
- Border Radius: `12px`
- Modal: `True` (blocks background)

---

## 🎯 INTERACTIONS & ANIMATIONS

### Hover States
- **Chat Item Hover:** Background changes to `#F0F2F5`
- **Button Hover:** Overlay color `#E7F5FF` with opacity change
- **Input Focus:** Border color changes to `#0088CC`

### Tap/Click States
- **Send Button:** Scale to `0.95` (slight press effect)
- **Chat Item:** Brief highlight then fade back
- **Emoji:** Scale to `1.1` then back (selection feedback)

### Loading States
- **Progress Ring:** `#0088CC` color
- **Text:** "Loading chats..." with animated dots

### Connection Status
- **Connected:** Green check, blue status
- **Connecting:** Orange sync icon (rotating)
- **Disconnected:** Red wifi off icon
- **Status Text:** Shows in AppBar subtitle

---

## ✅ TELEGRAM CONFORMANCE CHECKLIST

- ✅ Light blue primary color (#0088CC)
- ✅ Message bubble styling (18px + 4px tail)
- ✅ Avatar circles (56px with shadow)
- ✅ Unread badges (red circles with count)
- ✅ Date separators (centered text)
- ✅ Online status indicator (colored dot)
- ✅ Double check marks (blue when read)
- ✅ Typing indicators ("... is typing")
- ✅ Search functionality
- ✅ Dark mode support
- ✅ File attachment menu (colorful icons)
- ✅ Emoji picker (1,447 emojis)
- ✅ Group chat support
- ✅ Channel support
- ✅ Saved messages cloud storage

---

## 📦 IMPLEMENTATION FILES

| File | Purpose | Status |
|------|---------|--------|
| `theme.py` | Color & spacing constants | ✅ Complete |
| `views/message_view.py` | Message bubbles + input | ✅ Complete |
| `views/chats.py` | Chat list + avatars | ✅ Complete |
| `views/login.py` | Login/register screen | ✅ Fixed |
| `emoji_data.py` | 1,447 emojis + categories | ✅ Fixed |
| `error_handler.py` | Error snackbars | ✅ Complete |

---

## 🚀 USAGE

```python
from theme import LIGHT_COLORS, DARK_COLORS, FONT_SIZES, SPACING, RADIUS

# Use colors
bubble_color = LIGHT_COLORS["message_sent"]  # #EEFFDE

# Use spacing
padding = SPACING["lg"]  # 12px

# Use font sizes
title_size = FONT_SIZES["lg"]  # 16px

# Use radius
rounded = RADIUS["md"]  # 8px
```

---

## 🎉 RESULT

Perfect Telegram-style UI with:
- ✅ Exact color matching
- ✅ Perfect spacing & sizing
- ✅ Smooth interactions
- ✅ Dark mode support
- ✅ Mobile-first responsive design
- ✅ Accessible components

**Last Updated:** December 9, 2025  
**Status:** Production Ready ✅
