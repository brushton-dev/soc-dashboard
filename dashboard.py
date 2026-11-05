import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path

st.set_page_config(
    page_title="SOC Metrics Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

DATA_PATH = Path("data/security_events.csv")
SEVERITY_ORDER  = ["critical", "high", "medium", "low"]
SEVERITY_COLORS = {"critical": "#d62728", "high": "#ff7f0e", "medium": "#ffd700", "low": "#2ca02c"}
DAY_ORDER = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


@st.cache_data
def load() -> pd.DataFrame:
    if not DATA_PATH.exists():
        st.error("Data not found. Run `python generate_logs.py` first.")
        st.stop()
    df = pd.read_csv(DATA_PATH, parse_dates=["timestamp"])
    df["date"]        = df["timestamp"].dt.date
    df["hour"]        = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.day_name()
    return df


df = load()

# ── SIDEBAR ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("Filters")
    date_min = df["timestamp"].dt.date.min()
    date_max = df["timestamp"].dt.date.max()
    date_range = st.date_input(
        "Date range",
        value=(date_min, date_max),
        min_value=date_min,
        max_value=date_max,
    )
    sel_types = st.multiselect(
        "Event type",
        options=sorted(df["event_type"].unique()),
        default=sorted(df["event_type"].unique()),
    )
    sel_sev = st.multiselect(
        "Severity",
        options=SEVERITY_ORDER,
        default=SEVERITY_ORDER,
    )

if len(date_range) != 2:
    st.warning("Select a start and end date.")
    st.stop()

mask = (
    (df["timestamp"].dt.date >= date_range[0])
    & (df["timestamp"].dt.date <= date_range[1])
    & (df["event_type"].isin(sel_types))
    & (df["severity"].isin(sel_sev))
)
fdf = df[mask].copy()

# ── HEADER ────────────────────────────────────────────────────────────────────
st.title("SOC Security Metrics Dashboard")
st.caption(f"{len(fdf):,} events  ·  {date_range[0]} to {date_range[1]}")

# ── KPI TILES ─────────────────────────────────────────────────────────────────
total         = len(fdf)
critical_rate = (fdf["severity"] == "critical").sum() / total * 100 if total else 0
escalate_rate = (fdf["status"]   == "escalated").sum() / total * 100 if total else 0
block_rate    = (fdf["status"]   == "blocked").sum()   / total * 100 if total else 0
top_attack    = fdf["event_type"].mode()[0].replace("_", " ").title() if total else "—"

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Alerts",    f"{total:,}")
c2.metric("Critical Rate",   f"{critical_rate:.1f}%")
c3.metric("Escalation Rate", f"{escalate_rate:.1f}%")
c4.metric("Block Rate",      f"{block_rate:.1f}%")
c5.metric("Top Attack Type", top_attack)

st.divider()

# ── ROW 1: DAILY TIMELINE + SEVERITY BAR ──────────────────────────────────────
col_a, col_b = st.columns([3, 1])

with col_a:
    daily = (
        fdf.set_index("timestamp")
        .resample("D")["event_type"]
        .count()
        .rename("alerts")
        .reset_index()
    )
    fig = px.line(
        daily, x="timestamp", y="alerts",
        title="Daily Alert Volume",
        labels={"timestamp": "Date", "alerts": "Alerts"},
        color_discrete_sequence=["#1f77b4"],
    )
    fig.update_layout(height=280, margin=dict(t=36, b=0, l=0, r=0))
    st.plotly_chart(fig, use_container_width=True)

with col_b:
    sev_counts = (
        fdf["severity"]
        .value_counts()
        .reindex(SEVERITY_ORDER)
        .fillna(0)
        .rename_axis("severity")
        .reset_index(name="count")
    )
    fig = px.bar(
        sev_counts, x="severity", y="count",
        title="By Severity",
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        labels={"severity": "", "count": "Count"},
    )
    fig.update_layout(height=280, margin=dict(t=36, b=0, l=0, r=0), showlegend=False)
    st.plotly_chart(fig, use_container_width=True)

# ── ROW 2: ATTACK TYPE + TOP SOURCE IPs ───────────────────────────────────────
col_c, col_d = st.columns(2)

with col_c:
    type_counts = (
        fdf["event_type"]
        .value_counts()
        .rename_axis("type")
        .reset_index(name="count")
    )
    type_counts["type"] = type_counts["type"].str.replace("_", " ").str.title()
    fig = px.bar(
        type_counts, x="count", y="type",
        orientation="h",
        title="Alerts by Attack Type",
        labels={"count": "Alert Count", "type": ""},
        color_discrete_sequence=["#1f77b4"],
    )
    fig.update_layout(
        height=310, margin=dict(t=36, b=0, l=0, r=0),
        yaxis={"categoryorder": "total ascending"},
    )
    st.plotly_chart(fig, use_container_width=True)

with col_d:
    top_ips = (
        fdf["source_ip"]
        .value_counts()
        .head(10)
        .rename_axis("ip")
        .reset_index(name="alerts")
    )
    fig = px.bar(
        top_ips, x="alerts", y="ip",
        orientation="h",
        title="Top 10 Source IPs",
        labels={"alerts": "Alert Count", "ip": ""},
        color_discrete_sequence=["#d62728"],
    )
    fig.update_layout(
        height=310, margin=dict(t=36, b=0, l=0, r=0),
        yaxis={"categoryorder": "total ascending"},
    )
    st.plotly_chart(fig, use_container_width=True)

# ── HEATMAP: HOUR × DAY OF WEEK ───────────────────────────────────────────────
st.subheader("Alert Activity — Hour of Day × Day of Week")
present_days = [d for d in DAY_ORDER if d in fdf["day_of_week"].values]
heatmap_data = (
    fdf.groupby(["day_of_week", "hour"])
    .size()
    .unstack(fill_value=0)
    .reindex(present_days)
)
fig = go.Figure(go.Heatmap(
    z=heatmap_data.values,
    x=[f"{h:02d}:00" for h in heatmap_data.columns],
    y=heatmap_data.index.tolist(),
    colorscale="Reds",
    hovertemplate="Day: %{y}<br>Hour: %{x}<br>Alerts: %{z}<extra></extra>",
))
fig.update_layout(
    height=255,
    margin=dict(t=10, b=10, l=0, r=0),
    xaxis_title="Hour of Day",
    yaxis_title="",
)
st.plotly_chart(fig, use_container_width=True)

# ── RAW DATA ──────────────────────────────────────────────────────────────────
with st.expander("Raw event data"):
    st.dataframe(
        fdf[["timestamp", "source_ip", "destination_ip",
             "event_type", "severity", "host", "status"]]
        .sort_values("timestamp", ascending=False),
        use_container_width=True,
    )
