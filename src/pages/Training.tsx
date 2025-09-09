import { AnimatedBackground } from "@/components/ui/animated-background";
import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Clock, ArrowRight } from "lucide-react";
import { useEffect, useState } from "react";

interface TrainingItem {
  title: string;
  description: string;
  duration: string;
  level: string;
  tags: string[];
  href: string;
  featuredUrl?: string;
}

const Training = () => {
  const [items, setItems] = useState<TrainingItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const getLevelColor = (level: string) => {
    switch ((level || '').toLowerCase()) {
      case 'beginner': return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'intermediate': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'advanced': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'expert': return 'bg-red-500/20 text-red-400 border-red-500/30';
      default: return 'bg-primary/20 text-primary border-primary/30';
    }
  };

  useEffect(() => {
    let isMounted = true;
    async function load() {
      try {
        const res = await fetch('/trainings/index.json', { cache: 'no-store' });
        if (!res.ok) throw new Error(`Failed to load trainings: ${res.status}`);
        const data: TrainingItem[] = await res.json();
        if (isMounted) setItems(data);
      } catch (e: any) {
        if (isMounted) setError(e?.message || 'Failed to load trainings');
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
              <span className="text-gradient">Pwn Training</span>
            </h1>
            <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
              Covering topics from stack exploitation basics to advanced browser exploitation, this training is a WIP.
            </p>
          </div>
        </section>

        {/* Training Grid */}
        <section className="pb-20 px-6">
          <div className="max-w-7xl mx-auto">
            {loading && (
              <div className="text-center text-muted-foreground">Loading trainings…</div>
            )}
            {error && (
              <div className="text-center text-destructive">{error}</div>
            )}
            {!loading && !error && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                {items.map((training, index) => {
                  const isExternal = training.href.startsWith('http://') || training.href.startsWith('https://');
                  return (
                <Card 
                  key={index} 
                  className="group bg-card/50 backdrop-blur-sm border-border/50 hover:border-primary/30 transition-all duration-300 hacker-glow hover:scale-105 overflow-hidden"
                >
                  {/* Featured Image */}
                  {training.featuredUrl && (
                    <img
                      src={training.featuredUrl}
                      alt={`${training.title} cover`}
                      className="w-full h-40 object-cover"
                      loading="lazy"
                    />
                  )}

                  <CardHeader>
                    <CardTitle className="text-xl font-bold group-hover:text-primary transition-colors">
                      {training.title}
                    </CardTitle>
                    <CardDescription className="text-muted-foreground line-clamp-3">
                      {training.description}
                    </CardDescription>
                  </CardHeader>

                  <CardContent>
                    {/* Level and Duration */}
                    <div className="flex items-center gap-4 mb-4">
                          {training.level && (
                      <Badge className={`text-xs border ${getLevelColor(training.level)}`}>
                        {training.level}
                      </Badge>
                          )}
                          {training.duration && (
                      <div className="flex items-center gap-1 text-sm text-muted-foreground">
                        <Clock className="w-4 h-4" />
                        <span>{training.duration}</span>
                      </div>
                          )}
                    </div>

                    {/* Tags */}
                    <div className="flex flex-wrap gap-2 mb-4">
                      {training.tags.map((tag) => (
                        <Badge key={tag} variant="secondary" className="text-xs">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </CardContent>

                  <CardFooter>
                    <Button 
                      variant="ghost" 
                      className="w-full group-hover:bg-primary/10 group-hover:text-primary transition-colors"
                      asChild
                    >
                          <a href={training.href} {...(isExternal ? { target: '_blank', rel: 'noopener noreferrer' } : {})}>
                        Start Learning
                        <ArrowRight className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform" />
                      </a>
                    </Button>
                  </CardFooter>
                </Card>
                  );
                })}
            </div>
            )}
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
};

export default Training;