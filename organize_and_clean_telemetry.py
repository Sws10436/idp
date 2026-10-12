import json
import math
import csv
import os
import networkx as nx
import matplotlib.pyplot as plt

def organize_and_clean():
    json_path = "telemetry.json"
    edges_csv_path = "telemetry_graph_weighted_edges.csv"
    nodes_csv_path = "telemetry_graph_nodes.csv"
    preview_img_path = "telemetry_graph_preview.png"

    print(f"[*] Reading {json_path}...")
    with open(json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    raw_nodes = raw.get("nodes", {})
    raw_edges = raw.get("edges", {})
    raw_processes = raw_nodes.get("processes", [])
    raw_memory = raw_nodes.get("memory_regions", [])
    raw_sockets = raw_nodes.get("sockets", [])

    print(f"    - Original processes: {len(raw_processes)}")
    print(f"    - Original memory regions: {len(raw_memory)}")
    print(f"    - Original sockets: {len(raw_sockets)}")

    # 1. Filter out memory regions to KEEP ONLY unbacked executable regions (427 regions)
    # This cleans out 20,000+ redundant disk-backed image DLL pages that bloat the file
    cleaned_memory = [m for m in raw_memory if m.get("is_unbacked", False)]
    unbacked_ids = {m["id"] for m in cleaned_memory}
    memory_by_id = {m["id"]: m for m in cleaned_memory}
    print(f"    - Filtered unbacked executable memory regions: {len(cleaned_memory)}")

    # 2. Build process map and clean processes (strip massive thread ID arrays and raw module dumps)
    proc_map = {}
    cleaned_processes = []
    for p in raw_processes:
        pid = p["pid"]
        proc_node_id = f"proc_{pid}"
        thread_count = len(p.get("threads", []))
        module_count = len(p.get("modules", []))
        
        proc_map[pid] = {
            "node_id": proc_node_id,
            "pid": pid,
            "ppid": p.get("ppid", 0),
            "name": p.get("executable_name", ""),
            "path": p.get("executable_path", ""),
            "thread_count": thread_count,
            "module_count": module_count,
            "access_denied": p.get("access_denied", False)
        }

        # Compact process record for cleaned JSON
        cleaned_p = {
            "node_id": proc_node_id,
            "pid": pid,
            "ppid": p.get("ppid", 0),
            "executable_name": p.get("executable_name", ""),
            "executable_path": p.get("executable_path", ""),
            "thread_count": thread_count,
            "module_count": module_count,
            "access_denied": p.get("access_denied", False)
        }
        cleaned_processes.append(cleaned_p)

    # 3. Clean sockets
    cleaned_sockets = []
    socket_by_id = {}
    for s in raw_sockets:
        sock_id = s.get("id", "")
        socket_by_id[sock_id] = s
        cleaned_sockets.append({
            "node_id": sock_id,
            "pid": s.get("pid", 0),
            "protocol": s.get("protocol", ""),
            "local_address": s.get("local_address", ""),
            "local_port": s.get("local_port", 0),
            "remote_address": s.get("remote_address", ""),
            "remote_port": s.get("remote_port", 0),
            "state": s.get("state", "")
        })

    # 4. Construct Weighted Edges
    weighted_edges = []

    # 4a. Process -> Child Process (spawns)
    for e in raw_edges.get("spawns", []):
        ppid = e.get("parent_pid", 0)
        cpid = e.get("child_pid", 0)
        parent = proc_map.get(ppid)
        child = proc_map.get(cpid)
        if not parent or not child:
            continue
        
        # Lineage weight: base 1.0 + activity factor based on child thread count
        child_threads = child.get("thread_count", 0)
        w = round(1.0 + math.log2(child_threads + 1) * 0.25, 4)
        
        weighted_edges.append({
            "source": parent["node_id"],
            "target": child["node_id"],
            "source_type": "process",
            "target_type": "process",
            "relationship": "spawns",
            "weight": w,
            "source_label": f"{parent['name']} (PID {ppid})",
            "target_label": f"{child['name']} (PID {cpid})",
            "entropy": 0.0,
            "is_unbacked": 0,
            "detail": f"Spawns child process {child['name']} (threads={child_threads})"
        })

    # 4b. Process -> Unbacked Executable Memory (has_memory)
    # Shannon Entropy directly defines the weight (0.0 to 8.0)
    for e in raw_edges.get("has_memory", []):
        mem_id = e.get("memory_id", "")
        if mem_id not in unbacked_ids:
            continue  # Skip image-backed pages
        
        mem = memory_by_id.get(mem_id, {})
        pid = e.get("pid", mem.get("pid", 0))
        proc = proc_map.get(pid, {"name": f"PID_{pid}", "node_id": f"proc_{pid}"})
        
        entropy = round(float(mem.get("shannon_entropy", 0.0)), 4)
        protect = mem.get("protect_str", mem.get("protect", ""))
        size = mem.get("region_size", 0)

        # Weight is proportional to Shannon entropy
        # RWX allocations (Execute + Read + Write) get a severity boost of 1.25x
        rwx_boost = 1.25 if "READWRITE" in str(protect) else 1.0
        w = round(max(entropy * rwx_boost, 0.5), 4)

        weighted_edges.append({
            "source": proc["node_id"],
            "target": mem_id,
            "source_type": "process",
            "target_type": "memory_region",
            "relationship": "has_memory",
            "weight": w,
            "source_label": f"{proc['name']} (PID {pid})",
            "target_label": f"Unbacked Mem ({protect}, {size}B)",
            "entropy": entropy,
            "is_unbacked": 1,
            "detail": f"Unbacked page {protect}, size={size}B, Shannon Entropy={entropy}"
        })

    # 4c. Process -> Socket (connected_to)
    for e in raw_edges.get("connected_to", []):
        sock_id = e.get("socket_id", "")
        sock = socket_by_id.get(sock_id)
        if not sock:
            continue
        
        pid = e.get("pid", sock.get("pid", 0))
        proc = proc_map.get(pid, {"name": f"PID_{pid}", "node_id": f"proc_{pid}"})
        
        state = sock.get("state", "")
        proto = sock.get("protocol", "")
        lport = sock.get("local_port", 0)
        raddr = sock.get("remote_address", "*")
        rport = sock.get("remote_port", 0)

        # Network weight: ESTABLISHED = 3.0, LISTENING = 2.0, UDP = 1.5, other = 0.8
        if state == "ESTABLISHED":
            w = 3.0
        elif state == "LISTENING":
            w = 2.0
        elif "UDP" in proto:
            w = 1.5
        else:
            w = 0.8

        weighted_edges.append({
            "source": proc["node_id"],
            "target": sock_id,
            "source_type": "process",
            "target_type": "socket",
            "relationship": "connected_to",
            "weight": w,
            "source_label": f"{proc['name']} (PID {pid})",
            "target_label": f"{proto} :{lport} -> {raddr}:{rport} [{state}]",
            "entropy": 0.0,
            "is_unbacked": 0,
            "detail": f"{proto} connection to {raddr}:{rport} in state {state}"
        })

    print(f"    - Generated weighted edges: {len(weighted_edges)}")

    # Compute normalized weight (0.1 to 1.0) for visual plotting
    weights = [item["weight"] for item in weighted_edges]
    min_w = min(weights) if weights else 0.0
    max_w = max(weights) if weights else 1.0
    range_w = max_w - min_w if max_w > min_w else 1.0

    for item in weighted_edges:
        norm = 0.1 + 0.9 * ((item["weight"] - min_w) / range_w)
        item["weight_normalized"] = round(norm, 4)

    # 5. Write telemetry_graph_weighted_edges.csv
    print(f"[*] Writing {edges_csv_path}...")
    fieldnames = [
        "source", "target", "relationship", "weight", "weight_normalized",
        "source_type", "target_type", "source_label", "target_label",
        "entropy", "is_unbacked", "detail"
    ]
    with open(edges_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(weighted_edges)
    print(f"    [OK] Saved {len(weighted_edges)} weighted edges to {edges_csv_path}")

    # 6. Write telemetry_graph_nodes.csv
    print(f"[*] Writing {nodes_csv_path}...")
    nodes_list = []
    # Processes
    for p in cleaned_processes:
        nodes_list.append({
            "node_id": p["node_id"],
            "node_type": "process",
            "label": f"{p['executable_name']} (PID {p['pid']})",
            "pid": p["pid"],
            "name": p["executable_name"],
            "metric_1": p["thread_count"],     # threads
            "metric_2": p["module_count"],     # modules
            "extra_info": p["executable_path"]
        })
    # Memory regions
    for m in cleaned_memory:
        nodes_list.append({
            "node_id": m["id"],
            "node_type": "memory_region",
            "label": f"Unbacked Mem (H={m.get('shannon_entropy', 0):.2f})",
            "pid": m.get("pid", 0),
            "name": m.get("id", ""),
            "metric_1": round(float(m.get("shannon_entropy", 0.0)), 4), # entropy
            "metric_2": m.get("region_size", 0),                        # size in bytes
            "extra_info": m.get("protect_str", m.get("protect", ""))
        })
    # Sockets
    for s in cleaned_sockets:
        nodes_list.append({
            "node_id": s["node_id"],
            "node_type": "socket",
            "label": f"{s['protocol']} :{s['local_port']} [{s['state']}]",
            "pid": s.get("pid", 0),
            "name": s["protocol"],
            "metric_1": s["local_port"],
            "metric_2": s["remote_port"],
            "extra_info": f"{s['local_address']}:{s['local_port']} -> {s['remote_address']}:{s['remote_port']} ({s['state']})"
        })

    with open(nodes_csv_path, "w", newline="", encoding="utf-8") as f:
        node_fields = ["node_id", "node_type", "label", "pid", "name", "metric_1", "metric_2", "extra_info"]
        writer = csv.DictWriter(f, fieldnames=node_fields)
        writer.writeheader()
        writer.writerows(nodes_list)
    print(f"    [OK] Saved {len(nodes_list)} nodes to {nodes_csv_path}")

    # 7. Clean and Overwrite telemetry.json
    print(f"[*] Cleaning telemetry.json...")
    cleaned_json_edges = {
        "spawns": [
            {
                "source": e["source"],
                "target": e["target"],
                "relationship": "spawns",
                "weight": e["weight"],
                "weight_normalized": e["weight_normalized"]
            }
            for e in weighted_edges if e["relationship"] == "spawns"
        ],
        "has_memory": [
            {
                "source": e["source"],
                "target": e["target"],
                "relationship": "has_memory",
                "weight": e["weight"],
                "weight_normalized": e["weight_normalized"],
                "shannon_entropy": e["entropy"]
            }
            for e in weighted_edges if e["relationship"] == "has_memory"
        ],
        "connected_to": [
            {
                "source": e["source"],
                "target": e["target"],
                "relationship": "connected_to",
                "weight": e["weight"],
                "weight_normalized": e["weight_normalized"]
            }
            for e in weighted_edges if e["relationship"] == "connected_to"
        ]
    }

    # Clean memory nodes: remove redundant verbose fields
    cleaned_memory_nodes = []
    for m in cleaned_memory:
        cleaned_memory_nodes.append({
            "id": m["id"],
            "pid": m.get("pid", 0),
            "base_address": m.get("base_address", 0),
            "region_size": m.get("region_size", 0),
            "protect": m.get("protect_str", m.get("protect", "")),
            "is_unbacked": True,
            "shannon_entropy": round(float(m.get("shannon_entropy", 0.0)), 4)
        })

    cleaned_data = {
        "metadata": {
            "timestamp_utc": raw.get("metadata", {}).get("timestamp_utc", ""),
            "os_version": raw.get("metadata", {}).get("os_version", ""),
            "running_as_admin": raw.get("metadata", {}).get("running_as_admin", False),
            "total_processes": len(cleaned_processes),
            "unbacked_memory_regions": len(cleaned_memory_nodes),
            "total_sockets": len(cleaned_sockets),
            "total_weighted_edges": len(weighted_edges),
            "is_cleaned": True,
            "description": "Pruned graph telemetry retaining unbacked executable memory pages, processes, sockets, and weighted graph edges."
        },
        "nodes": {
            "processes": cleaned_processes,
            "memory_regions": cleaned_memory_nodes,
            "sockets": cleaned_sockets
        },
        "edges": cleaned_json_edges
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(cleaned_data, f, indent=2)

    new_size = os.path.getsize(json_path)
    print(f"    [OK] Cleaned {json_path} successfully! New size: {new_size:,} bytes (~{new_size / 1024:.1f} KB)")

    # 8. Generate a Visual Graph Preview Plot
    print(f"[*] Generating graph preview plot ({preview_img_path})...")
    G = nx.DiGraph()
    # Add subset of interesting nodes (processes with unbacked memory or sockets, plus their connections)
    active_sources = set()
    for e in weighted_edges:
        if e["relationship"] in ("has_memory", "connected_to"):
            active_sources.add(e["source"])

    sub_edges = [e for e in weighted_edges if e["source"] in active_sources][:250]
    for e in sub_edges:
        G.add_edge(e["source_label"], e["target_label"], weight=e["weight_normalized"], rel=e["relationship"])

    if len(G.nodes) > 0:
        plt.figure(figsize=(14, 10), facecolor="#0f172a")
        pos = nx.spring_layout(G, k=0.4, iterations=50, seed=42)
        
        edge_weights = [d["weight"] * 2.5 for u, v, d in G.edges(data=True)]
        edge_colors = ["#f59e0b" if d["rel"] == "has_memory" else "#38bdf8" if d["rel"] == "connected_to" else "#a855f7" for u, v, d in G.edges(data=True)]

        nx.draw_networkx_nodes(G, pos, node_size=60, node_color="#e2e8f0", alpha=0.9)
        nx.draw_networkx_edges(G, pos, width=edge_weights, edge_color=edge_colors, alpha=0.6, arrows=True, arrowsize=8)
        
        # Draw labels for top processes
        top_labels = {n: n for n in G.nodes if "(PID" in n and len(list(G.neighbors(n))) > 2}
        nx.draw_networkx_labels(G, pos, labels=top_labels, font_size=8, font_color="#ffffff", font_family="sans-serif")

        plt.title("Windows Host Telemetry: Weighted Graph Topology (Processes, Unbacked Memory, Sockets)", color="#f8fafc", fontsize=14, fontweight="bold", pad=20)
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(preview_img_path, dpi=200, facecolor="#0f172a")
        plt.close()
        print(f"    [OK] Graph preview saved to {preview_img_path}")

if __name__ == "__main__":
    organize_and_clean()
