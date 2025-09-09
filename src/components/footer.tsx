import { Badge } from "@/components/ui/badge";
import { Github, Linkedin, Youtube, Mail, Heart } from "lucide-react";

export const Footer = () => {
  const currentYear = new Date().getFullYear();
  
  const socialLinks = [
    { icon: Youtube, href: "https://youtube.com/tourpran", label: "YouTube" },
    { icon: Github, href: "https://github.com/tourpran", label: "GitHub" },
    { icon: Linkedin, href: "https://linkedin.com/in/tourpran", label: "LinkedIn" },
    { icon: Mail, href: "mailto:thepranavkrish04@gmail.com", label: "Email" },
  ];

  return (
    <footer className="relative py-16 px-6 mt-20">
      {/* Background Gradient */}
      <div className="absolute inset-0 bg-gradient-to-t from-background via-background/90 to-transparent"></div>
      
      <div className="relative max-w-7xl mx-auto">
        {/* Social Links (clean) */}
        <div className="flex items-center justify-center gap-6">
              {socialLinks.map(({ icon: Icon, href, label }) => (
                <a
                  key={label}
                  href={href}
                  target="_blank"
                  rel="noopener noreferrer"
              className="text-muted-foreground hover:text-primary transition-colors group"
              aria-label={label}
              title={label}
                >
                  <Icon className="w-5 h-5 group-hover:scale-110 transition-transform" />
                </a>
              ))}
        </div>

        {/* Bottom Bar */}
        <div className="border-t border-border/50 mt-12 pt-8 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-muted-foreground text-sm">
            © {currentYear} Pranav Krishna. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  );
};