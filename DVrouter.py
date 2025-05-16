from router import Router
import json
from packet import Packet


class DVrouter(Router):
    """Distance vector routing protocol implementation.

    Add your own class fields and initialization code (e.g. to create forwarding table
    data structures). See the `Router` base class for docstrings of the methods to
    override.
    """

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class - DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0

        # Forwarding table maps destination addresses to outgoing ports
        self.forwarding_table = {}  # {dst_addr: port}

        # Distance vector stores the cost to reach each destination
        self.distance_vector = {self.addr: 0}  # {dst_addr: cost}

        # Keep track of neighbors and their associated ports and costs
        self.neighbors = {}  # {neighbor_addr: (port, cost)}

        # Store the most recent distance vectors from neighbors
        self.neighbor_vectors = {}  # {neighbor_addr: {dst_addr: cost}}

        # For poison reverse
        self.next_hops = {}  # {dst_addr: neighbor_addr}

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:
            # Handle data packets for traceroute
            if packet.dst_addr in self.forwarding_table:
                self.send(self.forwarding_table[packet.dst_addr], packet)
        else:
            # Handle routing protocol packets (distance vector updates)
            try:
                content = json.loads(packet.content)
                src = content["src"]
                dv = content["dv"]

                # Get previous distance vector from this neighbor (if any)
                old_dv = self.neighbor_vectors.get(src, {})

                # Update our record of neighbor's distance vector
                self.neighbor_vectors[src] = dv

                # Determine if we need to recalculate routes based on this update
                if dv != old_dv:
                    changed = self._update_distance_vector()
                    if changed:
                        # If our distance vector changed, notify neighbors
                        self._broadcast_dv()
            except (json.JSONDecodeError, KeyError) as e:
                # Handle malformed packets
                pass

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        # Record the new neighbor
        self.neighbors[endpoint] = (port, cost)

        # Direct connection to neighbor
        old_cost = self.distance_vector.get(endpoint, float('inf'))
        if cost < old_cost:
            self.distance_vector[endpoint] = cost
            self.forwarding_table[endpoint] = port
            self.next_hops[endpoint] = endpoint  # Direct link

        # Send our current distance vector to the new neighbor
        dv_packet = Packet(Packet.ROUTING, self.addr, None, json.dumps({
            "src": self.addr,
            "dv": self._get_poisoned_dv(endpoint)
        }))
        self.send(port, dv_packet)

        # Recalculate routes with the new link
        changed = self._update_distance_vector()
        if changed:
            # If routes changed, broadcast updates to all neighbors
            self._broadcast_dv()

    def handle_remove_link(self, port):
        """Handle removed link."""
        # Find which neighbor was connected to this port
        endpoint = None
        for neighbor, (p, _) in self.neighbors.items():
            if p == port:
                endpoint = neighbor
                break

        if endpoint:
            # Remove the neighbor from our records
            del self.neighbors[endpoint]
            if endpoint in self.neighbor_vectors:
                del self.neighbor_vectors[endpoint]

            # Reset routes that used this neighbor
            affected_destinations = []
            for dst, next_hop in self.next_hops.items():
                if next_hop == endpoint:
                    affected_destinations.append(dst)

            # Remove direct link distance
            if endpoint in self.distance_vector and endpoint != self.addr:
                self.distance_vector[endpoint] = float('inf')

            # Recalculate routes after removing the link
            changed = self._update_distance_vector()

            if changed:
                # If routes changed, broadcast updates to all neighbors
                self._broadcast_dv()

    def _update_distance_vector(self):
        """Update distance vector based on neighbors' distance vectors.

        Returns:
            bool: True if distance vector changed, False otherwise
        """
        changed = False

        # Get all known destinations from our distance vector and neighbors'
        all_destinations = set(self.distance_vector.keys())
        for neighbor_dv in self.neighbor_vectors.values():
            all_destinations.update(neighbor_dv.keys())

        # For each destination, find the best route
        for dst in all_destinations:
            if dst == self.addr:
                continue  # Skip self (always 0)

            # Current best known cost to destination
            old_cost = self.distance_vector.get(dst, float('inf'))

            # Find minimum cost path to destination
            min_cost = float('inf')
            best_port = None
            best_next_hop = None

            # Check direct link first
            if dst in self.neighbors:
                min_cost = self.neighbors[dst][1]
                best_port = self.neighbors[dst][0]
                best_next_hop = dst

            # Check routes through neighbors
            for neighbor, (port, cost_to_neighbor) in self.neighbors.items():
                if neighbor in self.neighbor_vectors:
                    neighbor_dv = self.neighbor_vectors[neighbor]
                    if dst in neighbor_dv:
                        # Cost = cost to neighbor + neighbor's cost to destination
                        total_cost = cost_to_neighbor + neighbor_dv[dst]

                        # Update if found better route
                        if total_cost < min_cost:
                            min_cost = total_cost
                            best_port = port
                            best_next_hop = neighbor

            # Update distance vector and forwarding table if better route found
            if min_cost < float('inf'):
                if min_cost != old_cost:
                    self.distance_vector[dst] = min_cost
                    changed = True

                # Update forwarding table and next hop tracking
                self.forwarding_table[dst] = best_port
                self.next_hops[dst] = best_next_hop
            elif old_cost < float('inf'):
                # Route to destination is no longer available
                self.distance_vector[dst] = float('inf')
                if dst in self.forwarding_table:
                    del self.forwarding_table[dst]
                changed = True

        return changed

    def _get_poisoned_dv(self, neighbor=None):
        """Get distance vector with poison reverse applied.

        Args:
            neighbor: The neighbor to send poisoned routes to

        Returns:
            dict: Poisoned distance vector
        """
        if neighbor is None:
            return self.distance_vector.copy()

        poisoned_dv = self.distance_vector.copy()

        # Apply poison reverse: if we route through this neighbor to reach a destination,
        # tell the neighbor our cost is infinity (to avoid count-to-infinity problem)
        for dst, next_hop in self.next_hops.items():
            if next_hop == neighbor:
                poisoned_dv[dst] = float('inf')

        return poisoned_dv

    def _broadcast_dv(self):
        """Broadcast current distance vector to all neighbors."""
        for neighbor, (port, _) in self.neighbors.items():
            # Create packet with poisoned distance vector for this neighbor
            poisoned_dv = self._get_poisoned_dv(neighbor)
            dv_packet = Packet(Packet.ROUTING, self.addr, None, json.dumps({
                "src": self.addr,
                "dv": poisoned_dv
            }))
            self.send(port, dv_packet)

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            # Periodically broadcast our distance vector to all neighbors
            self._broadcast_dv()

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        return (f"DVrouter(addr={self.addr}, "
                f"dv={self.distance_vector}, "
                f"fwd_table={self.forwarding_table})")