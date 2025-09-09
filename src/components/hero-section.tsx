import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Github, Linkedin, Youtube, Mail, Download, ExternalLink } from "lucide-react";
import profileAvatar from "@/assets/profile-avatar.jpg";

export const HeroSection = () => {
  const socialLinks = [
    { icon: Youtube, href: "https://youtube.com/tourpran", label: "YouTube" },
    { icon: Github, href: "https://github.com/tourpran", label: "GitHub" },
    { icon: Linkedin, href: "https://linkedin.com/in/tourpran", label: "LinkedIn" },
    { icon: Mail, href: "mailto:thepranavkrish04@gmail.com", label: "Email" },
  ];

  return (
    <section className="relative min-h-screen flex items-center justify-center px-6">
      <div className="max-w-4xl mx-auto text-center space-y-8">
        {/* Profile Image */}
        <div className="relative mx-auto w-48 h-48 mb-8">
          <div className="absolute inset-0 rounded-full bg-gradient-to-r from-hacker-red to-hacker-orange opacity-20 animate-pulse"></div>
          <img
            src={profileAvatar}
            alt="Pranav Krishna"
            className="relative z-10 w-full h-full rounded-full object-cover border-4 border-primary/30 hacker-glow"
          />
        </div>

        {/* Main Heading */}
        <div className="space-y-4">
          <h1 className="text-6xl md:text-7xl font-bold tracking-tight">
            <span className="text-gradient">Pranav Krishna</span>
          </h1>
          <div className="flex flex-wrap justify-center gap-3">
            <Badge variant="outline" className="text-lg px-4 py-2 border-primary/50">
              CTFer
            </Badge>
            <Badge variant="outline" className="text-lg px-4 py-2 border-primary/50">
              Vuln Researcher
            </Badge>
          </div>
        </div>

        {/* Description */}
        <p className="text-xl md:text-2xl text-muted-foreground max-w-2xl mx-auto leading-relaxed">
          Expect content spanning from low-level stack exploits to demonstrations of real-world CVEs. 
        </p>

        {/* Social Links */}
        <div className="flex flex-wrap justify-center gap-4">
          {socialLinks.map(({ icon: Icon, href, label }) => (
            <Button
              key={label}
              variant="outline"
              size="lg"
              className="hacker-glow border-primary/30 hover:border-primary"
              asChild
            >
              <a href={href} target="_blank" rel="noopener noreferrer">
                <Icon className="w-5 h-5 mr-2" />
                {label}
                <ExternalLink className="w-4 h-4 ml-2" />
              </a>
            </Button>
          ))}
        </div>

        {/* Resume Download */}
        <div className="pt-4">
          <Button
            variant="default"
            size="lg"
            className="bg-gradient-to-r from-hacker-red to-hacker-orange hover:opacity-90 text-white font-semibold px-8 py-3"
            asChild
          >
            <a href="/images/my_resume/pranav_resume.pdf" download>
              <Download className="w-5 h-5 mr-2" />
              Download Resume
            </a>
          </Button>
        </div>

        {/* Scroll indicator */}
        <div className="absolute bottom-8 left-1/2 transform -translate-x-1/2 animate-bounce">
          <div className="w-6 h-10 border-2 border-primary/50 rounded-full p-1">
            <div className="w-1 h-3 bg-primary rounded-full mx-auto animate-pulse"></div>
          </div>
        </div>
      </div>
    </section>
  );
};