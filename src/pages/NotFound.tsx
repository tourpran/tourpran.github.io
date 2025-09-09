import { useLocation } from "react-router-dom";
import { useEffect, useRef, useState } from "react";
import * as d3 from "d3";
import { AnimatedBackground } from "@/components/ui/animated-background";
import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";

interface Node {
  id: string;
  name: string;
  type: "blog" | "writeup" | "training" | "tag";
  color: string;
  size: number;
  url?: string;
}

interface Link {
  source: string;
  target: string;
}

const NotFound = () => {
  const location = useLocation();
  const graphRef = useRef<SVGSVGElement | null>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  // Sample data from other pages
  const blogPosts = [
    { id: "holy-cow-pwnme25", name: "holy cow - pwnme25", tags: ["V8", "CTF", "Exploit"], url: "/posts/holy-cow-pwnme25.html" },
    { id: "v8-arrayshift-race", name: "v8 - ArrayShift Race Condition", tags: ["Browser", "V8", "ArrayShift", "TurboFan"], url: "/posts/v8-arrayshift-race-condition.html" },
    { id: "cve-2024-0517", name: "CVE-2024-0517 Quick Blog", tags: ["Browser", "V8", "Maglev", "CVE"], url: "/posts/cve-2024-0517.html" },
    { id: "v8-turbofan", name: "Understanding V8 Turbofan Optimizations", tags: ["V8", "Turbofan", "Compiler", "Optimization"], url: "/posts/v8-turbofan-optimizations" },
    { id: "browser-sandbox", name: "Browser Sandbox Escapes", tags: ["Browser", "Sandbox", "Escape", "Security"], url: "/posts/browser-sandbox-escapes" },
    { id: "memory-corruption", name: "Memory Corruption in JavaScript Engines", tags: ["Memory", "Corruption", "JavaScript", "Heap"], url: "/posts/memory-corruption-js-engines" }
  ];

  const writeups = [
    { id: "chrome-v8-sbx", name: "Chrome V8 Sandbox Escape", tags: ["V8", "Chrome", "Sandbox"], difficulty: "Hard" },
    { id: "firefox-jit", name: "Firefox JIT Exploitation", tags: ["Firefox", "JIT", "Exploitation"], difficulty: "Expert" },
    { id: "webkit-uaf", name: "WebKit Use-After-Free", tags: ["WebKit", "UAF", "Safari"], difficulty: "Medium" },
    { id: "v8-type-confusion", name: "V8 Type Confusion", tags: ["V8", "Type", "Confusion"], difficulty: "Hard" },
    { id: "browser-exploit-chain", name: "Browser Exploit Chain", tags: ["Browser", "Chain", "RCE"], difficulty: "Expert" }
  ];

  const training = [
    { id: "browser-exploitation", name: "Browser Exploitation Fundamentals", tags: ["Browser", "Fundamentals", "Exploitation"] },
    { id: "v8-internals", name: "V8 Engine Internals", tags: ["V8", "Internals", "Engine"] },
    { id: "js-engine-fuzzing", name: "JavaScript Engine Fuzzing", tags: ["JavaScript", "Fuzzing", "Engine"] },
    { id: "browser-security", name: "Modern Browser Security", tags: ["Browser", "Security", "Modern"] },
    { id: "exploit-development", name: "Advanced Exploit Development", tags: ["Exploit", "Development", "Advanced"] }
  ];

  // Create nodes and links
  const createGraphData = () => {
    const nodes: Node[] = [];
    const links: Link[] = [];
    const tagMap = new Map<string, string[]>();

    // Add blog nodes
    blogPosts.forEach(post => {
      nodes.push({
        id: post.id,
        name: post.name,
        type: "blog",
        color: "#8b5cf6",
        size: 8,
        url: post.url
      });

      post.tags.forEach(tag => {
        if (!tagMap.has(tag)) {
          tagMap.set(tag, []);
        }
        tagMap.get(tag)!.push(post.id);
      });
    });

    // Add writeup nodes
    writeups.forEach(writeup => {
      nodes.push({
        id: writeup.id,
        name: writeup.name,
        type: "writeup",
        color: "#10b981",
        size: 8
      });

      writeup.tags.forEach(tag => {
        if (!tagMap.has(tag)) {
          tagMap.set(tag, []);
        }
        tagMap.get(tag)!.push(writeup.id);
      });
    });

    // Add training nodes
    training.forEach(course => {
      nodes.push({
        id: course.id,
        name: course.name,
        type: "training",
        color: "#f59e0b",
        size: 8
      });

      course.tags.forEach(tag => {
        if (!tagMap.has(tag)) {
          tagMap.set(tag, []);
        }
        tagMap.get(tag)!.push(course.id);
      });
    });

    // Add tag nodes and create links
    tagMap.forEach((contentIds, tag) => {
      if (contentIds.length > 1) {
        const tagNodeId = `tag-${tag}`;
        nodes.push({
          id: tagNodeId,
          name: tag,
          type: "tag",
          color: "#6b7280",
          size: 4
        });

        // Link tag to all content that has this tag
        contentIds.forEach(contentId => {
          links.push({
            source: tagNodeId,
            target: contentId
          });
        });
      }
    });

    return { nodes, links };
  };

  const graphData = createGraphData();
  
  useEffect(() => {
    console.error("404 Error: User attempted to access non-existent route:", location.pathname);
  }, [location.pathname]);

  useEffect(() => {
    const updateDimensions = () => {
      setDimensions({
        width: window.innerWidth * 0.9,
        height: window.innerHeight * 0.7
      });
    };

    updateDimensions();
    window.addEventListener("resize", updateDimensions);
    return () => window.removeEventListener("resize", updateDimensions);
  }, []);

  useEffect(() => {
    if (!graphRef.current) return;

    const svg = d3.select(graphRef.current);
    svg.selectAll("*").remove();

    const width = dimensions.width;
    const height = dimensions.height;

    // Create simulation
    const simulation = d3.forceSimulation(graphData.nodes as any)
      .force("link", d3.forceLink(graphData.links as any).id((d: any) => d.id).distance(100))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2));

    // Create links
    const link = svg.append("g")
      .selectAll("line")
      .data(graphData.links)
      .enter().append("line")
      .attr("stroke", "rgba(255, 255, 255, 0.2)")
      .attr("stroke-width", 1);

    // Create nodes
    const node = svg.append("g")
      .selectAll("circle")
      .data(graphData.nodes)
      .enter().append("circle")
      .attr("r", (d: any) => d.size)
      .attr("fill", (d: any) => d.color)
      .attr("stroke", "rgba(255, 255, 255, 0.3)")
      .attr("stroke-width", 1)
      .style("cursor", "default")
      .call(d3.drag<any, any>()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended)
      );

    // Add labels
    const labels = svg.append("g")
      .selectAll("text")
      .data(graphData.nodes)
      .enter().append("text")
      .text((d: any) => d.name.length > 20 ? d.name.substring(0, 20) + "..." : d.name)
      .style("fill", "white")
      .style("fontSize", "10px")
      .style("textAnchor", "middle")
      .style("pointerEvents", "none");

    // Update positions on tick
    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => (d as any).source.x)
        .attr("y1", (d: any) => (d as any).source.y)
        .attr("x2", (d: any) => (d as any).target.x)
        .attr("y2", (d: any) => (d as any).target.y);

      node
        .attr("cx", (d: any) => (d as any).x)
        .attr("cy", (d: any) => (d as any).y);

      labels
        .attr("x", (d: any) => (d as any).x)
        .attr("y", (d: any) => (d as any).y + 20);
    });

    function dragstarted(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event: any, d: any) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragended(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    return () => {
      simulation.stop();
    };
  }, [dimensions, graphData]);

  return (
    <div className="relative min-h-screen">
      <AnimatedBackground />
      <Navigation />
      <main className="relative z-10">
        {/* Hero Section */}
        <section className="pt-32 pb-8 px-6">
          <div className="max-w-7xl mx-auto text-center">
            <h1 className="text-5xl md:text-6xl font-bold mb-6">
              <span className="text-gradient">lost ?</span>
            </h1>
            <p className="text-xl text-muted-foreground max-w-3xl mx-auto mb-8">
              Don't worry, its easy to get lost in this world. But come check out this cool obsidin rip-off. Oh and one last thing, don't try to make sense out of the graph, its AI crap.
            </p>
            <div className="flex justify-center gap-6 text-sm">
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded-full bg-purple-500" />
                <span>Blogs</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded-full bg-emerald-500" />
                <span>Writeups</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded-full bg-amber-500" />
                <span>Training</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded-full bg-gray-500" />
                <span>Tags</span>
              </div>
            </div>
          </div>
        </section>

        {/* Graph Container */}
        <section className="pb-20 px-6">
          <div className="max-w-7xl mx-auto">
            <div 
              className="bg-card/30 backdrop-blur-sm border border-border/50 rounded-lg overflow-hidden"
              style={{ height: "70vh" }}
            >
              <svg
                ref={graphRef}
                width={dimensions.width}
                height={dimensions.height}
                className="w-full h-full"
              />
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
};

export default NotFound;
