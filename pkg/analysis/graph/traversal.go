// pkg/analysis/graph/traversal.go
package graph

// DFS performs depth-first search starting from the given node.
// The visitor function is called for each node.
// Return false from visitor to stop traversal.
func DFS(g *Graph, startID string, visitor func(node Node) bool) {
	visited := make(map[string]bool)
	dfs(g, startID, visited, visitor)
}

func dfs(g *Graph, nodeID string, visited map[string]bool, visitor func(node Node) bool) bool {
	if visited[nodeID] {
		return true
	}
	visited[nodeID] = true

	node, ok := g.GetNode(nodeID)
	if !ok {
		return true
	}

	if !visitor(node) {
		return false
	}

	for _, childID := range g.Children(nodeID) {
		if !dfs(g, childID, visited, visitor) {
			return false
		}
	}

	return true
}
