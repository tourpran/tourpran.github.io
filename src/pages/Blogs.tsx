import { AnimatedBackground } from "@/components/ui/animated-background";
import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Calendar, Clock, ArrowRight } from "lucide-react";
import { useEffect, useState } from "react";

interface BlogPost {
  title: string;
  description: string;
  date: string;
  readTime: number | string;
  tags: string[];
  href: string;
  featuredUrl?: string;
}

const Blogs = () => {
  const [posts, setPosts] = useState<BlogPost[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    async function load() {
      try {
        const res = await fetch("/posts/index.json", { cache: "no-store" });
        if (!res.ok) throw new Error(`Failed to load posts: ${res.status}`);
        const data: BlogPost[] = await res.json();
        if (isMounted) setPosts(data);
      } catch (e: any) {
        if (isMounted) setError(e?.message || "Failed to load posts");
      } finally {
        if (isMounted) setLoading(false);
      }
    }
    load();
    return () => { isMounted = false; };
  }, []);

  return (
    <div className="relative min-h-screen">
      <AnimatedBackground />
      <Navigation />
      <main className="relative z-10">
        {/* Hero Section */}
        <section className="pt-32 pb-16 px-6">
          <div className="max-w-7xl mx-auto text-center">
            <h1 className="text-5xl md:text-6xl font-bold mb-6">
              <span className="text-gradient">Technical Blogs</span>
            </h1>
            <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Anything interesting I stumble upon in the field of security and vulnerabilities. 
            </p>
          </div>
        </section>

        {/* Blog Grid */}
        <section className="pb-20 px-6">
          <div className="max-w-7xl mx-auto">
            {loading && (
              <div className="text-center text-muted-foreground">Loading posts…</div>
            )}
            {error && (
              <div className="text-center text-destructive">{error}</div>
            )}
            {!loading && !error && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                {posts.map((post, index) => (
                  <Card 
                    key={index} 
                    className="group bg-card/50 backdrop-blur-sm border-border/50 hover:border-primary/30 transition-all duration-300 hacker-glow hover:scale-105 overflow-hidden"
                  >
                    {/* Featured Image */}
                    {post.featuredUrl && (
                      <img
                        src={post.featuredUrl}
                        alt={`${post.title} cover`}
                        className="w-full h-40 object-cover"
                        loading="lazy"
                      />
                    )}

                    <CardHeader>
                      <CardTitle className="text-xl font-bold group-hover:text-primary transition-colors">
                        {post.title}
                      </CardTitle>
                      <CardDescription className="text-muted-foreground line-clamp-3">
                        {post.description}
                      </CardDescription>
                    </CardHeader>

                    <CardContent>
                      {/* Tags */}
                      <div className="flex flex-wrap gap-2 mb-4">
                        {post.tags.map((tag) => (
                          <Badge key={tag} variant="secondary" className="text-xs">
                            {tag}
                          </Badge>
                        ))}
                      </div>

                      {/* Metadata */}
                      <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <div className="flex items-center gap-1">
                          <Calendar className="w-4 h-4" />
                          <span>{new Date(post.date).toLocaleDateString()}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Clock className="w-4 h-4" />
                          <span>{post.readTime}</span>
                        </div>
                      </div>
                    </CardContent>

                    <CardFooter>
                      <Button 
                        variant="ghost" 
                        className="w-full group-hover:bg-primary/10 group-hover:text-primary transition-colors"
                        asChild
                      >
                        <a href={post.href}>
                          Read More
                          <ArrowRight className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform" />
                        </a>
                      </Button>
                    </CardFooter>
                  </Card>
                ))}
              </div>
            )}
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
};

export default Blogs;
