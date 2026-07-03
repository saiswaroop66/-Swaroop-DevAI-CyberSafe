import plotly.express as px
import pandas as pd


class DashboardCharts:

    # -------------------------------
    # Threat Distribution Pie Chart
    # -------------------------------

    def threat_pie(self, distribution):

        if not distribution:
            return None

        df = pd.DataFrame({
            "Threat": list(distribution.keys()),
            "Count": list(distribution.values())
        })

        fig = px.pie(
            df,
            names="Threat",
            values="Count",
            title="Threat Distribution"
        )

        fig.update_layout(
            template="plotly_dark",
            height=450
        )

        return fig

    # -------------------------------
    # Severity Bar Chart
    # -------------------------------

    def severity_bar(self, metrics):

        df = pd.DataFrame({

            "Severity": [
                "Critical",
                "High",
                "Medium",
                "Low"
            ],

            "Count": [

                metrics["critical"],
                metrics["high"],
                metrics["medium"],
                metrics["low"]

            ]
        })

        fig = px.bar(

            df,

            x="Severity",

            y="Count",

            title="Severity Breakdown"

        )

        fig.update_layout(

            template="plotly_dark",

            height=450

        )

        return fig

    # -------------------------------
    # Top Attacking IPs
    # -------------------------------

    def ip_chart(self, ip_dict):

        if not ip_dict:
            return None

        df = pd.DataFrame({

            "IP": list(ip_dict.keys()),

            "Requests": list(ip_dict.values())

        })

        df = df.sort_values(

            by="Requests",

            ascending=False

        ).head(10)

        fig = px.bar(

            df,

            x="IP",

            y="Requests",

            title="Top Attacking IPs"

        )

        fig.update_layout(

            template="plotly_dark",

            height=450

        )

        return fig

    # -------------------------------
    # Dashboard Gauge
    # -------------------------------

    def risk_gauge(self, score):

        fig = px.scatter()

        fig.update_layout(

            template="plotly_dark",

            title=f"Risk Score : {score}/100",

            height=300,

            xaxis=dict(visible=False),

            yaxis=dict(visible=False),

            annotations=[

                dict(

                    text=f"<b>{score}%</b>",

                    showarrow=False,

                    font=dict(

                        size=40

                    )

                )

            ]

        )

        return fig