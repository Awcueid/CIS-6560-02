import os
import pandas as pd
import plotly.express as px
import streamlit as st

# ==========================================
# [Configuration]
# ==========================================
FILE_PATH = "asana/Context-Aware_Vulnuerability_Prioritization_Engine.csv"

# Set Streamlit page configuration to wide layout
st.set_page_config(page_title="Project Calendar Viewer", layout="wide")

st.title("Project Schedule Timeline Calendar")

# 1. Automatically load the file from the fixed path
if os.path.exists(FILE_PATH):
    try:
        # Detect extension type and parse accordingly
        if FILE_PATH.endswith(".csv"):
            df = pd.read_csv(FILE_PATH)
        else:
            df = pd.read_excel(FILE_PATH)

        # 2. Data Cleaning & Preparation
        df["Name"] = df["Name"].fillna("Untitled Task")
        df["Assignee"] = df["Assignee"].fillna("Unassigned")
        df["Priority"] = df["Priority"].fillna("None")

        # Standardize date columns to datetime objects
        df["Start Date"] = pd.to_datetime(df["Start Date"], errors="coerce")
        df["Due Date"] = pd.to_datetime(df["Due Date"], errors="coerce")
        df["Created At"] = pd.to_datetime(df["Created At"], errors="coerce")

        # Handle edge cases for missing dates
        df["Due Date"] = df["Due Date"].fillna(df["Start Date"])
        df["Start Date"] = df["Start Date"].fillna(
            df["Due Date"].fillna(df["Created At"])
        )

        # Filter out any tasks that still don't have valid start/end metrics
        df = df.dropna(subset=["Start Date", "Due Date"])

        # 3. Fix the 2-Month Window ending strictly on December 3, 2026
        project_end_date = pd.to_datetime("2026-12-03")
        timeline_start_date = project_end_date - pd.DateOffset(months=2)  # 2026-10-03

        # Filter dataset to include tasks overlapping with this specific period
        df = df[
            (df["Start Date"] <= project_end_date) & (df["Due Date"] >= timeline_start_date)
        ]

        if df.empty:
            st.error("Error: No tasks found within the fixed 2-month project time frame.")
        else:
            # Add 1 day so single-day tasks occupy a full grid day block visually
            df["Due_Date_Visual"] = df["Due Date"] + pd.to_timedelta(1, unit="D")

            # 4. Sidebar Filtering controls
            st.sidebar.header("Filter Options")
            color_option = st.sidebar.selectbox(
                "Color Bars By:", ["Assignee", "Priority", "Section/Column"]
            )
            selected_assignee = st.sidebar.multiselect(
                "Filter by Assignee:",
                options=df["Assignee"].unique(),
                default=df["Assignee"].unique(),
            )

            # Apply selection filters to dataset
            df_filtered = df[df["Assignee"].isin(selected_assignee)]

            # 5. Generate & Render Interactive Plotly Timeline Chart (Gantt Chart)
            if not df_filtered.empty:
                fig = px.timeline(
                    df_filtered,
                    x_start="Start Date",
                    x_end="Due_Date_Visual",
                    y="Name",
                    color=color_option,
                    title="Fixed 2-Month Project Timeline (Ending Dec 03, 2026)",
                    hover_data=[
                        "Start Date",
                        "Due Date",
                        "Assignee",
                        "Priority",
                    ],
                    color_discrete_sequence=px.colors.qualitative.Pastel,
                )

                # Reversing y-axis positions puts the earliest tasks at the top
                fig.update_yaxes(autorange="reversed")
                
                # Enforce the strict fixed 2-month range on the X-axis
                fig.update_layout(
                    xaxis_title="Timeline Calendar",
                    yaxis_title="Tasks",
                    hovermode="y unified",
                    xaxis_range=[timeline_start_date, project_end_date],
                    height=max(400, len(df_filtered) * 35),  # Dynamically scales chart height
                )

                # Output interactive Gantt chart inside Streamlit
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning(
                    "No tasks match the selected filters. Please adjust your criteria in the sidebar."
                )

    except Exception as e:
        st.error(f"An error occurred while parsing the file. Details: {e}")
else:
    st.error(f"File not found at target directory: {os.path.abspath(FILE_PATH)}")
