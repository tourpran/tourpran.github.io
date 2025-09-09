import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync, existsSync, copyFileSync } from 'fs';
import { join, dirname, basename, extname } from 'path';
import { fileURLToPath } from 'url';
import matter from 'gray-matter';
import showdown from 'showdown';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Random gradients for cards
const GRADIENTS = [
  'from-purple-500 to-pink-500',
  'from-blue-500 to-cyan-500', 
  'from-emerald-500 to-teal-500',
  'from-orange-500 to-amber-500',
  'from-red-500 to-rose-500',
  'from-indigo-500 to-violet-500',
  'from-fuchsia-500 to-pink-500',
  'from-lime-500 to-green-500',
  'from-teal-500 to-cyan-500',
  'from-sky-500 to-blue-500'
];

function pickGradientFromSlug(slug) {
  const hash = slug.split('').reduce((a, b) => {
    a = ((a << 5) - a) + b.charCodeAt(0);
    return a & a;
  }, 0);
  return GRADIENTS[Math.abs(hash) % GRADIENTS.length];
}

function escapeAttr(str) {
  return String(str).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function slugifyFilename(filename) {
  return basename(filename, extname(filename)).toLowerCase().replace(/[^a-z0-9-]/g, '-');
}

function estimateReadTime(content) {
  const wordsPerMinute = 200;
  const wordCount = content.split(/\s+/).length;
  return Math.ceil(wordCount / wordsPerMinute);
}

function deriveExcerpt(content, maxLength = 160) {
  const plainText = content.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
  return plainText.length > maxLength ? plainText.substring(0, maxLength) + '...' : plainText;
}

function createMarkdownConverter() {
  return new showdown.Converter({
    tables: true,
    strikethrough: true,
    tasklists: true,
    ghCodeBlocks: true,
    ghCompatibleHeaderId: true,
    headerLevelStart: 1,
    simplifiedAutoLink: true,
    excludeTrailingPunctuationFromURLs: true,
    literalMidWordUnderscores: true,
    simpleLineBreaks: true,
    requireSpaceBeforeHeadingText: false,
    ghMentions: true,
    encodeEmails: true,
    openLinksInNewWindow: false,
    backslashEscapesHTMLTags: false,
    emoji: true,
    underline: false,
    ellipsis: true,
    completeHTMLDocument: false,
    metadata: false,
    splitAdjacentBlockquotes: false,
    moreStyling: true
  });
}

function generateTOC(content) {
  const headingRegex = /^(#{1,4})\s+(.+)$/gm;
  const headings = [];
  let match;
  
  while ((match = headingRegex.exec(content)) !== null) {
    const level = match[1].length;
    const text = match[2].trim();
    const id = text
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .trim()
      .replace(/\s+/g, '-');
    headings.push({ level, text, id });
  }
  
  if (headings.length === 0) return '';
  
  let html = '<nav class="toc-sidebar">';
  html += '<h3 class="toc-title">Table of Contents</h3>';
  html += '<ul class="toc-list">';
  
  let currentLevel = 1;
  for (const heading of headings) {
    while (currentLevel < heading.level) {
      html += '<ul class="toc-sublist">';
      currentLevel++;
    }
    while (currentLevel > heading.level) {
      html += '</ul>';
      currentLevel--;
    }
    html += `<li class="toc-item toc-level-${heading.level}"><a href="#${heading.id}" class="toc-link">${escapeAttr(heading.text)}</a></li>`;
  }
  
  while (currentLevel > 1) {
    html += '</ul>';
    currentLevel--;
  }
  
  html += '</ul></nav>';
  return html;
}

function convertYouTubeLinksToEmbeds(html) {
  const shortcodeRegex = /\{\{\s*<\s*youtube\s+([A-Za-z0-9_-]{11})\s*>\s*\}\}/g;
  const toIframe = (id) => `<div class="video-embed"><iframe src="https://www.youtube.com/embed/${id}" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen loading="lazy"></iframe></div>`;
  const out = html.replace(shortcodeRegex, (_m, id) => toIframe(id));
  return out.replace(/<p>\s*(<div class=\"video-embed\">[\s\S]*?<\/div>)\s*<\/p>/g, '$1');
}

function renderHtml({ title, description, date, readTime, tags, content, markdownContent, accentGradient, previousWriteup, nextWriteup, featuredUrl, event, difficulty, points }) {
  const gradient = accentGradient || pickGradientFromSlug(slugifyFilename(title));
  const tagPills = (tags || []).map(tag => 
    `<span class="bg-blue-500/20 text-blue-300 px-2 py-1 rounded text-xs">${escapeAttr(tag)}</span>`
  ).join(' ');
  
  const tocHtml = generateTOC(markdownContent);
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeAttr(title)} | CTF Writeup</title>
    <meta name="description" content="${escapeAttr(description)}">
    <link href="/src/index.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css" />
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <style>
        body { 
            background: linear-gradient(135deg, #0c0c0c 0%, #1a1a1a 100%);
            color: #e0e0e0;
        }
        .code-block {
            background: #1e1e1e;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 1rem;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
        }
        .gradient-text {
            background: linear-gradient(135deg, #f97316, #f59e0b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .video-embed { position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden; border-radius: 8px; border: 1px solid #374151; background: #0f0f0f; margin: 1.5rem 0; }
        .video-embed iframe { position: absolute; top: 0; left: 0; width: 100%; height: 100%; }
        .toc-sidebar {
            position: fixed;
            top: 2rem;
            left: 1rem;
            max-height: calc(100vh - 4rem);
            overflow-y: auto;
            background: #1a1a1a;
            border: 1px solid #374151;
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-right: 0;
            width: 280px;
            flex-shrink: 0;
            z-index: 10;
        }
        .toc-title {
            font-size: 0.875rem;
            font-weight: 600;
            color: #9ca3af;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 1rem;
            border-bottom: 1px solid #374151;
            padding-bottom: 0.5rem;
        }
        .toc-list { list-style: none; padding: 0; margin: 0; }
        .toc-sublist { list-style: none; padding-left: 0.5rem; margin-top: 0.25rem; }
        .toc-item { margin: 0.25rem 0; }
        .toc-level-2 { padding-left: 0.25rem; }
        .toc-level-3 { padding-left: 0.75rem; }
        .toc-level-4 { padding-left: 1.25rem; }
        .toc-link { display: block; color: #9ca3af; text-decoration: none; font-size: 0.875rem; line-height: 1.5; padding: 0.25rem 0; border-radius: 0.25rem; transition: all 0.2s; }
        .toc-link:hover { color: #60a5fa; background: #1f2937; padding-left: 0.5rem; }
        @media (max-width: 1024px) { .toc-sidebar { display: none; } }
        .prose h1 { background: linear-gradient(135deg, #f97316, #f59e0b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; font-size: 2.5rem; font-weight: 800; margin-top: 3rem; margin-bottom: 1.5rem; }
        .prose h2 { background: linear-gradient(135deg, #f97316, #f59e0b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; font-size: 2rem; font-weight: 700; margin-top: 3rem; margin-bottom: 1rem; border-bottom: 2px solid #374151; padding-bottom: 0.5rem; }
        .prose h3 { background: linear-gradient(135deg, #f97316, #f59e0b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; font-size: 1.5rem; font-weight: 600; margin-top: 2rem; margin-bottom: 0.75rem; }
        .prose h4 { background: linear-gradient(135deg, #f97316, #f59e0b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; font-size: 1.25rem; font-weight: 600; margin-top: 1.5rem; margin-bottom: 0.5rem; }
        .prose p { margin-bottom: 1.5rem; line-height: 1.7; color: #d1d5db; }
        .prose strong { color: #f3f4f6; font-weight: 600; }
        .prose code { background: #1e1e1e; color: #fbbf24; padding: 0.25rem 0.5rem; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.9em; }
        .prose pre { background: #1e1e1e; border: 1px solid #333; border-radius: 8px; padding: 1.5rem; overflow-x: auto; margin: 2rem 0; }
        .prose pre code { background: transparent; color: #e5e7eb; padding: 0; border-radius: 0; }
        .prose blockquote { background:rgb(93, 45, 26); color:rgb(255, 255, 255); border-left: 4px solid #ff8c00; padding: 1rem 1.25rem; margin: 1.25rem 0; border-radius: calc(var(--radius) - 2px); }
        .prose ul, .prose ol { list-style-color: #ff8c00; list-style-type: disc; list-style-position: outside; margin: 1.5rem 0; padding-left: 2rem; }
        .prose li { margin: 0.5rem 0; color: #d1d5db; }
        .prose li::marker { color: #ff8c00 !important; }
        .prose ol li { list-style-type: decimal; }
        .prose img { border-radius: 8px; margin: 2rem 0; max-width: 100%; }
        .prose hr { border: none; height: 2px; background: linear-gradient(90deg, transparent, #374151, transparent); margin: 3rem 0; }
        .prose a { color: rgb(3, 203, 146); text-decoration: underline; }
        </style>
</head>
<body class="min-h-screen">
    <div class="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-4 py-8 relative">
        <header class="mb-12">
            <a href="/writeups" class="text-emerald-400 hover:text-emerald-300 mb-4 inline-block">← Back</a>
            <h1 class="text-4xl md:text-5xl font-bold mb-4">
                <span class="gradient-text">${escapeAttr(title)}</span>
            </h1>
            ${featuredUrl ? `<div class="mb-8"><img src="${featuredUrl}" alt="${escapeAttr(title)} cover image" class="w-full h-64 md:h-80 object-cover rounded-lg shadow" loading="eager"></div>` : ''}
            <div class="flex items-center gap-4 text-sm text-gray-400 mb-6">
                <span>${new Date(date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</span>
                <span>•</span>
                <span>${readTime} min read</span>
                ${event ? `<span>•</span><span>${escapeAttr(event)}</span>` : ''}
                ${difficulty ? `<span>•</span><span>${escapeAttr(difficulty)}</span>` : ''}
                ${typeof points === 'number' ? `<span>•</span><span>${points} pts</span>` : ''}
                ${tags && tags.length ? '<span>•</span><div class="flex gap-2">' + tagPills + '</div>' : ''}
            </div>
        </header>

        <div class="flex flex-col lg:flex-row justify-start gap-6">
            ${tocHtml ? `<aside class="hidden lg:block">${tocHtml}</aside>` : ''}
            <article class="prose prose-invert max-w-none ml-0 lg:max-w-6xl lg:ml-10">
${convertYouTubeLinksToEmbeds(content)}
            </article>
        </div>
        <!-- Navigation -->
        <nav class="mt-16 pt-8 border-t border-gray-700">
            <div class="flex justify-between items-center">
                <div class="flex-1">
                    ${previousWriteup ? `<a href="${previousWriteup.href}" class="inline-flex items-center text-emerald-400 hover:text-emerald-300 transition-colors">
                        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"></path>
                        </svg>
                        <div class="text-left">
                            <div class="text-xs text-gray-400">Previous</div>
                            <div class="font-medium">${previousWriteup.title}</div>
                        </div>
                    </a>` : "<div></div>"}
                </div>
                <div class="flex-1 text-center">
                    <a href="/writeups" class="text-emerald-400 hover:text-emerald-300 transition-colors font-medium">All Writeups</a>
                </div>
                <div class="flex-1 text-right">
                    ${nextWriteup ? `<a href="${nextWriteup.href}" class="inline-flex items-center text-emerald-400 hover:text-emerald-300 transition-colors">
                        <div class="text-right">
                            <div class="text-xs text-gray-400">Next</div>
                            <div class="font-medium">${nextWriteup.title}</div>
                        </div>
                        <svg class="w-4 h-4 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                        </svg>
                    </a>` : "<div></div>"}
                </div>
            </div>
        </nav>
        </nav>
    </div>
<script>window.addEventListener('DOMContentLoaded',()=>{try{document.querySelectorAll('pre code').forEach((el)=>window.hljs&&window.hljs.highlightElement(el));}catch(e){console.warn('hljs init failed',e);}});</script>
</body>
</html>`;
}

function collectMarkdownFiles(dir, files = []) {
  const items = readdirSync(dir);
  for (const item of items) {
    const fullPath = join(dir, item);
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      collectMarkdownFiles(fullPath, files);
    } else if (item.endsWith('.md')) {
      files.push(fullPath);
    }
  }
  return files;
}

function resolveSlug(filePath) {
  const relativePath = filePath.replace(join(__dirname, '../content/writeups/'), '');
  const pathParts = relativePath.split('/');
  
  if (pathParts[pathParts.length - 1] === 'index.md') {
    return pathParts.slice(0, -1).join('/');
  }
  
  return relativePath.replace('.md', '');
}

function convertFile(filePath, previousWriteup, nextWriteup) {
  const content = readFileSync(filePath, 'utf8');
  const { data, content: markdownContent } = matter(content);
  
  const slug = data.slug || resolveSlug(filePath);
  const title = data.title || 'Untitled';
  const description = data.description || deriveExcerpt(markdownContent);
  const date = data.date || new Date().toISOString();
  const readTime = data.readTime || estimateReadTime(markdownContent);
  const tags = data.tags || [];
  const accentGradient = data.accentGradient || pickGradientFromSlug(slug);
  const event = data.event || '';
  const difficulty = data.difficulty || '';
  const points = typeof data.points === 'number' ? data.points : undefined;
  
  const converter = createMarkdownConverter();
  const htmlContent = converter.makeHtml(markdownContent);
  
  // Determine featured image and copy to public directory if present
  const sourceDir = dirname(filePath);
  const featuredSource = join(sourceDir, 'featured.png');
  let featuredUrl = '';
  try {
    if (existsSync(featuredSource)) {
      const outputAssetsDir = join(__dirname, '../public/writeups', slug);
      mkdirSync(outputAssetsDir, { recursive: true });
      const featuredDest = join(outputAssetsDir, 'featured.png');
      copyFileSync(featuredSource, featuredDest);
      featuredUrl = `/writeups/${slug}/featured.png`;
    }
  } catch (_) {}
  
  const html = renderHtml({
    title,
    description,
    date,
    readTime,
    tags,
    content: htmlContent,
    markdownContent: markdownContent,
    accentGradient,
    previousWriteup,
    nextWriteup,
    featuredUrl,
    event,
    difficulty,
    points
  });
  
  const outputPath = join(__dirname, '../public/writeups', `${slug}.html`);
  const outputDir = dirname(outputPath);
  mkdirSync(outputDir, { recursive: true });
  writeFileSync(outputPath, html);
  
  return {
    href: `/writeups/${slug}.html`,
    title,
    description,
    date,
    readTime,
    tags,
    gradient: accentGradient,
    slug,
    featuredUrl,
    event,
    difficulty,
    points
  };
}

function buildAll() {
  const writeupsDir = join(__dirname, '../content/writeups');
  if (!existsSync(writeupsDir)) {
    console.log('No writeups directory found, skipping.');
    return;
  }
  const markdownFiles = collectMarkdownFiles(writeupsDir);
  
  console.log(`Found ${markdownFiles.length} writeup markdown files`);
  
  const writeupsMeta = [];
  
  // First pass: collect basic metadata
  for (const file of markdownFiles) {
    try {
      const content = readFileSync(file, 'utf8');
      const { data } = matter(content);
      const slug = data.slug || resolveSlug(file);
      const title = data.title || 'Untitled';
      const date = data.date || new Date().toISOString();
      
      writeupsMeta.push({ slug, title, date, file });
    } catch (error) {
      console.error(`✗ Error processing ${file}:`, error.message);
    }
  }
  
  // Sort by date (newest first)
  writeupsMeta.sort((a, b) => new Date(b.date) - new Date(a.date));
  
  // Second pass: generate HTML with navigation
  for (let i = 0; i < writeupsMeta.length; i++) {
    try {
      const previousWriteup = i > 0 ? {
        title: writeupsMeta[i - 1].title,
        href: `/writeups/${writeupsMeta[i - 1].slug}.html`
      } : null;
      
      const nextWriteup = i < writeupsMeta.length - 1 ? {
        title: writeupsMeta[i + 1].title,
        href: `/writeups/${writeupsMeta[i + 1].slug}.html`
      } : null;
      
      const meta = convertFile(writeupsMeta[i].file, previousWriteup, nextWriteup);
      writeupsMeta[i] = meta;
      console.log(`✓ Generated: ${meta.slug}.html`);
    } catch (error) {
      console.error(`✗ Error processing ${writeupsMeta[i].file}:`, error.message);
    }
  }
  
  // Write index.json (moved to /api/writeups)
  const indexPath = join(__dirname, '../public/api/writeups/index.json');
  const indexDir = dirname(indexPath);
  mkdirSync(indexDir, { recursive: true });
  writeFileSync(indexPath, JSON.stringify(writeupsMeta, null, 2));
  console.log(`✓ Generated: api/writeups/index.json with ${writeupsMeta.length} writeups`);
}

buildAll(); 