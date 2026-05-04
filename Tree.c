#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXN 100005

typedef struct {
    int to, next;
    long long w;
} Edge;

Edge edges[2 * MAXN];
int head[MAXN], ecnt;
long long dist[MAXN];
int visited[MAXN];
int n;

void add_edge(int u, int v, long long w) {
    edges[ecnt].to   = v;
    edges[ecnt].w    = w;
    edges[ecnt].next = head[u];
    head[u] = ecnt++;
}

/* BFS from src; returns the farthest node found */
int bfs(int src) {
    int *queue = (int *)malloc(n * sizeof(int));
    int front = 0, back = 0;

    for (int i = 1; i <= n; i++) { visited[i] = 0; dist[i] = 0; }

    visited[src] = 1;
    queue[back++] = src;
    int farthest = src;

    while (front < back) {
        int u = queue[front++];
        for (int i = head[u]; i != -1; i = edges[i].next) {
            int v = edges[i].to;
            if (!visited[v]) {
                visited[v] = 1;
                dist[v] = dist[u] + edges[i].w;
                if (dist[v] > dist[farthest])
                    farthest = v;
                queue[back++] = v;
            }
        }
    }

    free(queue);
    return farthest;
}

int main() {
    scanf("%d", &n);

    memset(head, -1, sizeof(head));
    ecnt = 0;

    for (int i = 0; i < n - 1; i++) {
        int u, v;
        long long w;
        scanf("%d %d %lld", &u, &v, &w);
        add_edge(u, v, w);
        add_edge(v, u, w);
    }

    if (n == 1) {
        printf("0\n");
        return 0;
    }

    /* Pass 1: farthest from node 1 */
    int u = bfs(1);
    /* Pass 2: farthest from u — this distance is the diameter */
    int v = bfs(u);

    printf("%lld\n", dist[v]);
    return 0;
}
