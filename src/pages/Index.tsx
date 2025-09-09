import { AnimatedBackground } from "@/components/ui/animated-background";
import { Navigation } from "@/components/navigation";
import { HeroSection } from "@/components/hero-section";
import { BlogSection } from "@/components/blog-section";
import { Footer } from "@/components/footer";

const Index = () => {
  return (
    <div className="relative min-h-screen">
      <AnimatedBackground />
      <Navigation />
      <main className="relative z-10">
        <HeroSection />
        <BlogSection />
      </main>
      <Footer />
    </div>
  );
};

export default Index;
