import { AnimatedBackground } from "@/components/ui/animated-background";
import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Calendar, Clock, Trophy, ArrowRight } from "lucide-react";
import { useEffect, useState } from "react";

interface WriteupMeta {
  title: string;
  description: string;
  event?: string;
  date: string;
  readTime: number | string;
  difficulty?: string;
  tags: string[];
  gradient?: string;
  href: string;
  points?: number;
  featuredUrl?: string;
}

const Writeups = () => {
  const [writeups, setWriteups] = useState<WriteupMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    async function load() {
      try {
        const res = await fetch("/api/writeups/index.json", { cache: "no-store" });
        if (!res.ok) throw new Error(`Failed to load writeups: ${res.status}`);
        const data: WriteupMeta[] = await res.json();
        if (isMounted) setWriteups(data);
      } catch (e: any) {
        if (isMounted) setError(e?.message || "Failed to load writeups");
      } finally {
        if (isMounted) setLoading(false);
      }
    }
    load();
    return () => { isMounted = false; };
  }, []);

  const getDifficultyColor = (difficulty?: string) => {
    if (!difficulty) return 'bg-primary/20 text-primary border-primary/30';
    switch (difficulty.toLowerCase()) {
      case 'easy': return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'hard': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'expert': return 'bg-red-500/20 text-red-400 border-red-500/30';
      default: return 'bg-primary/20 text-primary border-primary/30';
    }
  };

  return (
    <div className="relative min-h-screen">
      <AnimatedBackground />
      <Navigation />
      <main className="relative z-10">
        {/* Hero Section */}
        <section className="pt-32 pb-16 px-6">
          <div className="max-w-7xl mx-auto text-center">
            <h1 className="text-5xl md:text-6xl font-bold mb-6">
              <span className="text-gradient">CTF Writeups</span>
            </h1>
            <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
              Quick and short writeups to the challenges I come across various CTFs. Try them on your own before reading the solution.
            </p>
          </div>
        </section>

        {/* Writeups Grid */}
        <section className="pb-20 px-6">
          <div className="max-w-7xl mx-auto">
            {loading && (
              <div className="text-center text-muted-foreground">Loading writeups…</div>
            )}
            {error && (
              <div className="text-center text-destructive">{error}</div>
            )}
            {!loading && !error && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                {writeups.map((w, index) => (
                  <Card 
                    key={index} 
                    className="group bg-card/50 backdrop-blur-sm border-border/50 hover:border-primary/30 transition-all duration-300 hacker-glow hover:scale-105 overflow-hidden"
                  >
                    {/* Featured Image */}
                    {w.featuredUrl && (
                      <img
                        src={w.featuredUrl}
                        alt={`${w.title} cover`}
                        className="w-full h-40 object-cover"
                        loading="lazy"
                      />
                    )}

                    <CardHeader>
                       {/* Event and Points */}
                       <div className="flex items-center justify-between mb-2">
                         {w.event && (
                           <Badge variant="outline" className="text-xs border-primary/50">
                             {w.event}
                           </Badge>
                         )}
                         {typeof w.points === 'number' && (
                           <div className="flex items-center gap-1 text-xs text-muted-foreground">
                             <Trophy className="w-3 h-3" />
                             <span>{w.points}pts</span>
                           </div>
                         )}
                       </div>
                       
                       <CardTitle className="text-xl font-bold group-hover:text-primary transition-colors">
                         {w.title}
                       </CardTitle>
                       
                       <CardDescription className="text-muted-foreground line-clamp-3">
                         {w.description}
                       </CardDescription>
                     </CardHeader>

                    <CardContent>
                      {/* Difficulty */}
                      {w.difficulty && (
                        <div className="mb-4">
                          <Badge className={`text-xs border ${getDifficultyColor(w.difficulty)}`}>
                            {w.difficulty}
                          </Badge>
                        </div>
                      )}

                      {/* Tags */}
                      <div className="flex flex-wrap gap-2 mb-4">
                        {w.tags.map((tag) => (
                          <Badge key={tag} variant="secondary" className="text-xs">
                            {tag}
                          </Badge>
                        ))}
                      </div>

                      {/* Metadata */}
                      <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <div className="flex items-center gap-1">
                          <Calendar className="w-4 h-4" />
                          <span>{new Date(w.date).toLocaleDateString()}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Clock className="w-4 h-4" />
                          <span>{w.readTime}</span>
                        </div>
                      </div>
                    </CardContent>

                    <CardFooter>
                      <Button 
                        variant="ghost" 
                        className="w-full group-hover:bg-primary/10 group-hover:text-primary transition-colors"
                        asChild
                      >
                        <a href={w.href}>
                          Read Writeup
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

export default Writeups;