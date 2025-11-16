# Hypersend Backend Deployment Guide: Google Cloud Platform + Docker Hub + GitHub Actions

**Objective:** Deploy Hypersend backend to GCP to handle lakhs (hundreds of thousands) of users while optimizing your $300 credit over 90 days.

---

## Table of Contents
1. Cost Optimization Strategy
2. Architecture Overview
3. Prerequisites
4. Step 1: Setup Google Cloud Platform Account
5. Step 2: Create GCP Compute Engine Instance
6. Step 3: Setup MongoDB on GCP
7. Step 4: Configure Docker Hub Repository
8. Step 5: Create GitHub Actions Workflow
9. Step 6: Configure NGINX Reverse Proxy with SSL
10. Step 7: Deploy Backend and Test
11. Step 8: Scaling & Monitoring
12. Cost Management Tips

---

## Cost Optimization Strategy

Your $300 credit for 90 days (~10 days per $10) requires careful budgeting. Here's the optimal approach:

| Component                   | Option                     | Monthly Cost   | Reason                   |
|-----------------------------|----------------------------|----------------|--------------------------|
| **Compute**                 | e2-small Spot VM           | ~$5-8/month    | 60-91% discount price    |
| **Storage (Persistent Disk)**| 100GB Standard             | ~$4/month      | MongoDB & file uploads   |
| **Database**                | MongoDB Atlas Free M0      | $0/month       | 512MB free tier          |
| **Container Registry**      | Docker Hub                 | $0/month       | Free image hosting       |
| **Reverse Proxy**           | NGINX (on VM)              | $0/month       | Built into OS            |
| **SSL Certificate**         | Let's Encrypt              | $0/month       | Free via Certbot         |
| **Load Balancing**          | Skip initially             | $0/month       | Add on >1M users         |
| **Total (Month 1-3)**       |                            | ~$9-12/month   | Safe budget              |

---

## Architecture Overview

```
GitHub Actions ---> Docker Hub ---> GCP Compute VM
   |                |                    |
   |                |                    |--NGINX Proxy
   |                |                    |--FastAPI Backend
   |                |                    |--MongoDB Atlas/Local
   |                |                    |--File Storage
```

---

## Prerequisites

- GitHub repo for Hypersend
- Docker Hub account
- Google Cloud account ($300 trial)
- Domain name (for SSL & user trust)
- Local: Git, Docker, gcloud CLI

---

## Step 1: Setup Google Cloud Platform Account

- Create new project via console or cli
- Enable required APIs: Compute, Container Registry, Cloud Storage
- Create Service Account for SSH/CI

## Step 2: Create GCP Compute Engine Instance

- Use e2-small Spot VM for savings
- Attach 100GB persistent disk for uploads
- Use Container-Optimized OS
- Set up firewall rules for HTTP, HTTPS, SSH
- Mount /data/uploads for file storage

## Step 3: Setup MongoDB on GCP

### Option A: MongoDB Atlas Free Tier
- Create M0 cluster, whitelist IP, get connection string

### Option B: Local MongoDB on VM
- Install MongoDB, configure data dir as /data/mongodb

## Step 4: Configure Docker Hub Repository
- Create private/public repo for backend
- Generate access token for GitHub Actions

## Step 5: Create GitHub Actions Workflow
- Build and push Docker image on push
- SSH to VM and deploy/pull latest image
- Health check endpoint `/docs`

## Step 6: Configure NGINX Reverse Proxy with SSL
- Install NGINX
- Setup config for FastAPI backend proxy, large uploads
- Issue SSL via Certbot for HTTPS

## Step 7: Deploy Backend and Test
- Clone repo, set env vars, login Docker Hub
- Use docker-compose for backend up
- Test endpoints, user registration, uploads

## Step 8: Scaling & Monitoring
- Monitor CPU, memory, disk usage
- Upgrade VM if load grows, or create managed group and load balancer for multi-VM horizontal scale
- When MongoDB Atlas Free tier is full, upgrade in increments

## Cost Management Tips
- Use Spot VM, delete old uploads, set GCP billing alerts
- Monitor egress (network transfer charges may spike beyond $300 on very high traffic)
- Use CDN for file downloads if serving huge uploads

---

**Last Updated:** 16 Nov 2025
