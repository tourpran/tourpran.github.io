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

function convertYouTubeLinksToEmbeds(html) {
  const shortcodeRegex = /\{\{\s*<\s*youtube\s+([A-Za-z0-9_-]{11})\s*>\s*\}\}/g;
  const toIframe = (id) => `<div class="video-embed"><iframe src="https://www.youtube.com/embed/${id}" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen loading="lazy"></iframe></div>`;
  const out = html.replace(shortcodeRegex, (_m, id) => toIframe(id));
  return out.replace(/<p>\s*(<div class="video-embed">[\s\S]*?<\/div>)\s*<\/p>/g, '$1');
}

function renderHtml({ title, description, date, readTime, tags, content, accentGradient, previousPost, nextPost, featuredUrl }) {
  const gradient = accentGradient || pickGradientFromSlug(slugifyFilename(title));
  const tagPills = (tags || []).map(tag => 
    `<span class="bg-blue-500/20 text-blue-300 px-2 py-1 rounded text-xs">${escapeAttr(tag)}</span>`
  ).join(' ');
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeAttr(title)} | Security Research Blog</title>
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
        .prose h1 {
            background: linear-gradient(135deg, #f97316, #f59e0b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
            font-size: 2.5rem;
            font-weight: 800;
            margin-top: 3rem;
            margin-bottom: 1.5rem;
        }
        .prose h2 {
            background: linear-gradient(135deg, #f97316, #f59e0b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
            font-size: 2rem;
            font-weight: 700;
            margin-top: 3rem;
            margin-bottom: 1rem;
            border-bottom: 2px solid #374151;
            padding-bottom: 0.5rem;
        }
        .prose h3 {
            background: linear-gradient(135deg, #f97316, #f59e0b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
            font-size: 1.5rem;
            font-weight: 600;
            margin-top: 2rem;
            margin-bottom: 0.75rem;
        }
        .prose h4 {
            background: linear-gradient(135deg, #f97316, #f59e0b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
            font-size: 1.25rem;
            font-weight: 600;
            margin-top: 1.5rem;
            margin-bottom: 0.5rem;
        }
        .prose p {
            margin-bottom: 1.5rem;
            line-height: 1.7;
            color: #d1d5db;
        }
        .prose strong {
            color: #f3f4f6;
            font-weight: 600;
        }
        .prose code {
            background: #1e1e1e;
            color: #fbbf24;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        .prose pre {
            background: #1e1e1e;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 1.5rem;
            overflow-x: auto;
            margin: 2rem 0;
        }
        .prose pre code {
            background: transparent;
            color: #e5e7eb;
            padding: 0;
            border-radius: 0;
        }
        .prose blockquote {
          background:rgb(93, 45, 26);
          color:rgb(255, 255, 255);
          border-left: 4px solid #ff8c00;
          padding: 1rem 1.25rem;
          margin: 1.25rem 0;
          border-radius: calc(var(--radius) - 2px);
        }
        .prose ul, .prose ol {
            list-style-color: #ff8c00;
            list-style-type: disc;
            list-style-position: outside;
            margin: 1.5rem 0;
            padding-left: 2rem;
        }
        .prose li {
            margin: 0.5rem 0;
            color: #d1d5db;
        }
        .prose li::marker {
            color: #ff8c00 !important;
        }
        .prose ol li {
            list-style-type: decimal;
        }
        .prose table {
            margin: 2rem 0;
            background: #1e1e1e;
            border-radius: 8px;
            overflow: hidden;
        }
        .prose th, .prose td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid #333;
        }
        .prose th {
            background: #2d2d2d;
            color: #f3f4f6;
            font-weight: 600;
        }
        .prose img {
            border-radius: 8px;
            margin: 2rem 0;
            max-width: 100%;
        }
        .prose hr {
            border: none;
            height: 2px;
            background: linear-gradient(90deg, transparent, #374151, transparent);
            margin: 3rem 0;
        }
        .prose a { color: rgb(3, 203, 146); text-decoration: underline; }
    </style>
</head>
<body class="min-h-screen">
    <div class="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-4 py-8 relative">
        <header class="mb-12">
            <a href="/blogs" class="text-emerald-400 hover:text-emerald-300 mb-4 inline-block">← Back</a>
            <h1 class="text-4xl md:text-5xl font-bold mb-4">
                <span class="gradient-text">${escapeAttr(title)}</span>
            </h1>
            ${featuredUrl ? `<div class="mb-8"><img src="${featuredUrl}" alt="${escapeAttr(title)} cover image" class="w-full h-64 md:h-80 object-cover rounded-lg shadow" loading="eager"></div>` : ''}
            <div class="flex items-center gap-4 text-sm text-gray-400 mb-6">
                <span>${new Date(date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</span>
                <span>•</span>
                <span>${readTime} min read</span>
                <span>•</span>
                <div class="flex gap-2">${tagPills}</div>
            </div>
        </header>

        <article class="prose prose-invert max-w-none">
${convertYouTubeLinksToEmbeds(content)}
        </article>
        
        <!-- Navigation -->
        <nav class="mt-16 pt-8 border-t border-gray-700">
            <div class="flex justify-between items-center">
                <div class="flex-1">
                    ${previousPost ? `<a href="${previousPost.href}" class="inline-flex items-center text-emerald-400 hover:text-emerald-300 transition-colors">
                        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"></path>
                        </svg>
                        <div class="text-left">
                            <div class="text-xs text-gray-400">Previous</div>
                            <div class="font-medium">${previousPost.title}</div>
                        </div>
                    </a>` : "<div></div>"}
                </div>
                <div class="flex-1 text-center">
                    <a href="/blogs" class="text-emerald-400 hover:text-emerald-300 transition-colors font-medium">All Posts</a>
                </div>
                <div class="flex-1 text-right">
                    ${nextPost ? `<a href="${nextPost.href}" class="inline-flex items-center text-emerald-400 hover:text-emerald-300 transition-colors">
                        <div class="text-right">
                            <div class="text-xs text-gray-400">Next</div>
                            <div class="font-medium">${nextPost.title}</div>
                        </div>
                        <svg class="w-4 h-4 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                        </svg>
                    </a>` : "<div></div>"}
                </div>
            </div>
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
  const relativePath = filePath.replace(join(__dirname, '../content/posts/'), '');
  const pathParts = relativePath.split('/');
  
  if (pathParts[pathParts.length - 1] === 'index.md') {
    return pathParts.slice(0, -1).join('/');
  }
  
  return relativePath.replace('.md', '');
}

function convertFile(filePath, previousPost, nextPost) {
  const content = readFileSync(filePath, 'utf8');
  const { data, content: markdownContent } = matter(content);
  
  const slug = data.slug || resolveSlug(filePath);
  const title = data.title || 'Untitled';
  const description = data.description || deriveExcerpt(markdownContent);
  const date = data.date || new Date().toISOString();
  const readTime = data.readTime || estimateReadTime(markdownContent);
  const tags = data.tags || [];
  const accentGradient = data.accentGradient || pickGradientFromSlug(slug);
  
  const converter = createMarkdownConverter();
  const htmlContent = converter.makeHtml(markdownContent);
  
  // Determine featured image and copy to public directory if present
  const sourceDir = dirname(filePath);
  const featuredSource = join(sourceDir, 'featured.png');
  let featuredUrl = '';
  try {
    if (existsSync(featuredSource)) {
      const outputAssetsDir = join(__dirname, '../public/posts', slug);
      mkdirSync(outputAssetsDir, { recursive: true });
      const featuredDest = join(outputAssetsDir, 'featured.png');
      copyFileSync(featuredSource, featuredDest);
      featuredUrl = `/posts/${slug}/featured.png`;
    }
  } catch (_) {}
  
  const html = renderHtml({
    title,
    description,
    date,
    readTime,
    tags,
    content: htmlContent,
    accentGradient,
    previousPost,
    nextPost,
    featuredUrl
  });
  
  const outputPath = join(__dirname, '../public/posts', `${slug}.html`);
  const outputDir = dirname(outputPath);
  mkdirSync(outputDir, { recursive: true });
  writeFileSync(outputPath, html);
  
  return {
    href: `/posts/${slug}.html`,
    title,
    description,
    date,
    readTime,
    tags,
    slug,
    featuredUrl
  };
}

function buildAll() {
  const postsDir = join(__dirname, '../content/posts');
  const markdownFiles = collectMarkdownFiles(postsDir);
  
  console.log(`Found ${markdownFiles.length} markdown files`);
  
  const postsMeta = [];
  
  // First pass: collect basic metadata
  for (const file of markdownFiles) {
    try {
      const content = readFileSync(file, "utf8");
      const { data } = matter(content);
      const slug = data.slug || resolveSlug(file);
      const title = data.title || "Untitled";
      const date = data.date || new Date().toISOString();
      
      postsMeta.push({
        slug,
        title,
        date,
        file
      });
    } catch (error) {
      console.error(`✗ Error processing ${file}:`, error.message);
    }
  }
  
  // Sort by date (newest first)
  postsMeta.sort((a, b) => new Date(b.date) - new Date(a.date));
  
  // Second pass: generate HTML with navigation
  for (let i = 0; i < postsMeta.length; i++) {
    try {
      const previousPost = i > 0 ? {
        title: postsMeta[i - 1].title,
        href: `/posts/${postsMeta[i - 1].slug}.html`
      } : null;
      
      const nextPost = i < postsMeta.length - 1 ? {
        title: postsMeta[i + 1].title,
        href: `/posts/${postsMeta[i + 1].slug}.html`
      } : null;
      
      const meta = convertFile(postsMeta[i].file, previousPost, nextPost);
      postsMeta[i] = meta;
      console.log(`✓ Generated: ${meta.slug}.html`);
    } catch (error) {
      console.error(`✗ Error processing ${postsMeta[i].file}:`, error.message);
    }
  }
  
  // Write index.json
  const indexPath = join(__dirname, '../public/posts/index.json');
  writeFileSync(indexPath, JSON.stringify(postsMeta, null, 2));
  console.log(`✓ Generated: posts/index.json with ${postsMeta.length} posts`);
}

buildAll();
