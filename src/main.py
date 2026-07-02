import bz2
import json
import os

import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


DATA_PATH = "data/wls_day-01.bz2"
OUTPUT_DIR = "outputs"

AUTH_EVENT_IDS = {4624, 4625, 4648, 4672}

MAX_RECORDS = 200000


def load_lanl_auth_events(file_path):
    records = []

    with bz2.open(file_path, "rt") as file:
        for i, line in enumerate(file):
            if i >= MAX_RECORDS:
                break

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_id = record.get("EventID")

            if event_id in AUTH_EVENT_IDS:
                source = record.get("Source") or record.get("LogHost")
                destination = record.get("Destination") or record.get("LogHost")
                username = record.get("UserName") or record.get("SubjectUserName") or "UNKNOWN"

                records.append({
                    "time": record.get("Time"),
                    "event_id": event_id,
                    "username": username,
                    "source": source,
                    "destination": destination,
                    "log_host": record.get("LogHost"),
                    "logon_type": record.get("LogonType"),
                    "status": record.get("Status"),
                    "auth_package": record.get("AuthenticationPackage"),
                    "process_name": record.get("ProcessName")
                })

    df = pd.DataFrame(records)
    df = df.dropna(subset=["source", "destination"])

    return df


def build_graph(df):
    graph = nx.DiGraph()

    for _, row in df.iterrows():
        source = row["source"]
        destination = row["destination"]
        user = row["username"]

        if graph.has_edge(source, destination):
            graph[source][destination]["weight"] += 1
            graph[source][destination]["users"].add(user)
        else:
            graph.add_edge(source, destination, weight=1, users={user})

    return graph


def extract_features(df, graph):
    edge_frequency = df.groupby(["source", "destination"]).size().to_dict()
    user_destination_count = df.groupby("username")["destination"].nunique().to_dict()
    user_source_count = df.groupby("username")["source"].nunique().to_dict()

    features = []

    for _, row in df.iterrows():
        source = row["source"]
        destination = row["destination"]
        username = row["username"]
        event_id = row["event_id"]

        features.append({
            "time": row["time"],
            "event_id": event_id,
            "username": username,
            "source": source,
            "destination": destination,
            "edge_frequency": edge_frequency.get((source, destination), 1),
            "user_unique_destinations": user_destination_count.get(username, 1),
            "user_unique_sources": user_source_count.get(username, 1),
            "source_out_degree": graph.out_degree(source),
            "destination_in_degree": graph.in_degree(destination),
            "is_failed_logon": 1 if event_id == 4625 else 0,
            "is_explicit_credential_logon": 1 if event_id == 4648 else 0,
            "is_special_privilege": 1 if event_id == 4672 else 0
        })

    return pd.DataFrame(features)


def detect_anomalies(feature_df):
    model_columns = [
        "edge_frequency",
        "user_unique_destinations",
        "user_unique_sources",
        "source_out_degree",
        "destination_in_degree",
        "is_failed_logon",
        "is_explicit_credential_logon",
        "is_special_privilege"
    ]

    X = feature_df[model_columns].fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        contamination=0.03,
        random_state=42
    )

    feature_df["prediction"] = model.fit_predict(X_scaled)
    feature_df["anomaly_score"] = model.decision_function(X_scaled)
    feature_df["is_suspicious"] = feature_df["prediction"].apply(
        lambda value: "Yes" if value == -1 else "No"
    )

    return feature_df


def save_graph_image(graph, results_df):
    suspicious_edges = set(
        zip(
            results_df[results_df["is_suspicious"] == "Yes"]["source"],
            results_df[results_df["is_suspicious"] == "Yes"]["destination"]
        )
    )

    top_edges = sorted(
        graph.edges(data=True),
        key=lambda edge: edge[2].get("weight", 1),
        reverse=True
    )[:80]

    small_graph = nx.DiGraph()
    for source, destination, attrs in top_edges:
        small_graph.add_edge(source, destination, **attrs)

    pos = nx.spring_layout(small_graph, seed=42)

    edge_colors = [
        "red" if (source, destination) in suspicious_edges else "gray"
        for source, destination in small_graph.edges()
    ]

    plt.figure(figsize=(14, 10))
    nx.draw_networkx_nodes(small_graph, pos, node_size=700)
    nx.draw_networkx_labels(small_graph, pos, font_size=7)
    nx.draw_networkx_edges(
        small_graph,
        pos,
        edge_color=edge_colors,
        arrows=True,
        arrowsize=15,
        width=1.5
    )

    plt.title("LANL Host Authentication Graph - Suspicious Edges Highlighted")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/network_graph.png", dpi=300)
    plt.close()


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Loading LANL authentication events...")
    df = load_lanl_auth_events(DATA_PATH)

    print(f"Loaded {len(df)} authentication events.")
    df.to_csv(f"{OUTPUT_DIR}/processed_auth_events.csv", index=False)

    print("Building graph...")
    graph = build_graph(df)

    print(f"Graph nodes: {graph.number_of_nodes()}")
    print(f"Graph edges: {graph.number_of_edges()}")

    print("Extracting graph-based features...")
    feature_df = extract_features(df, graph)

    print("Running anomaly detection...")
    results_df = detect_anomalies(feature_df)

    print("Saving results...")
    results_df.to_csv(f"{OUTPUT_DIR}/anomaly_results.csv", index=False)

    print("Creating graph image...")
    save_graph_image(graph, results_df)

    suspicious = results_df[results_df["is_suspicious"] == "Yes"]
    print("\nTop suspicious events:")
    print(
        suspicious[
            [
                "time",
                "event_id",
                "username",
                "source",
                "destination",
                "anomaly_score",
                "is_suspicious"
            ]
        ].head(20)
    )

    print("\nDone.")
    print("Check outputs/anomaly_results.csv")
    print("Check outputs/network_graph.png")


if __name__ == "__main__":
    main()