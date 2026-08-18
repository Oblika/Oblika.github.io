import { defineCollection } from 'astro:content';
import { z } from 'astro/zod';
import { glob } from 'astro/loaders';

const writeups = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/writeups' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    date: z.coerce.date(),
    platform: z.string(),
    difficulty: z.string().optional(),
    category: z.string(),
    tags: z.array(z.string()).default([]),
    featured: z.boolean().default(false),
    readingTime: z.string().optional(),
    thumbnail: z.string().optional(),
  }),
});

export const collections = { writeups };
