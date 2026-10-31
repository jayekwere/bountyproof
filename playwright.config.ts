import { defineConfig } from '@playwright/test';
export default defineConfig({testDir:'./tests/browser',workers:1,timeout:20000,use:{browserName:'chromium',headless:true},reporter:[['list'],['json',{outputFile:'evidence/browser-results.json'}]]});
