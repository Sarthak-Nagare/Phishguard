/**
 * PhishGuard — Phishing URL Detection
 * Landing Page Interactive Scripts
 * 
 * Features:
 * 1. Mobile menu toggle (open/close drawer)
 * 2. Sticky navbar shadow & blur enhancement on scroll
 * 3. Auto-close mobile drawer when any link is clicked
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Element References
  const mobileMenuBtn = document.getElementById('mobileMenuBtn');
  const navMenu = document.getElementById('navMenu');
  const siteHeader = document.querySelector('.site-header');
  const navLinks = document.querySelectorAll('.nav-link');

  // --------------------------------------------------------------------------
  // 1. Mobile Navigation Toggle
  // --------------------------------------------------------------------------
  if (mobileMenuBtn && navMenu) {
    mobileMenuBtn.addEventListener('click', () => {
      const isExpanded = mobileMenuBtn.getAttribute('aria-expanded') === 'true';
      
      // Toggle menu open state
      navMenu.classList.toggle('open');
      mobileMenuBtn.classList.toggle('active');
      
      // Update accessibility attribute
      mobileMenuBtn.setAttribute('aria-expanded', !isExpanded);
    });

    // Close mobile menu when clicking outside
    document.addEventListener('click', (event) => {
      if (!navMenu.contains(event.target) && !mobileMenuBtn.contains(event.target)) {
        navMenu.classList.remove('open');
        mobileMenuBtn.classList.remove('active');
        mobileMenuBtn.setAttribute('aria-expanded', 'false');
      }
    });
  }

  // --------------------------------------------------------------------------
  // 2. Auto-close mobile menu when a navigation link is clicked
  // --------------------------------------------------------------------------
  navLinks.forEach((link) => {
    link.addEventListener('click', () => {
      if (navMenu && navMenu.classList.contains('open')) {
        navMenu.classList.remove('open');
        if (mobileMenuBtn) {
          mobileMenuBtn.classList.remove('active');
          mobileMenuBtn.setAttribute('aria-expanded', 'false');
        }
      }
    });
  });

  // --------------------------------------------------------------------------
  // 3. Smooth Scrolling for Navigation & Action Links
  // --------------------------------------------------------------------------
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener('click', (e) => {
      const targetId = anchor.getAttribute('href');
      
      if (targetId === '#top' || targetId === '#') {
        e.preventDefault();
        window.scrollTo({ top: 0, behavior: 'smooth' });
      } else if (targetId === '#how-it-works' || targetId === '#features' || targetId === '#about') {
        const targetElement = document.querySelector(targetId);
        if (targetElement) {
          e.preventDefault();
          targetElement.scrollIntoView({ behavior: 'smooth' });
        }
      } else if (targetId === '#login' || targetId === '#get-started') {
        // Visual placeholder buttons for future authentication implementation
        e.preventDefault();
      }
    });
  });

  // --------------------------------------------------------------------------
  // 4. Navbar scroll effect (add elevation class when scrolled)
  // --------------------------------------------------------------------------
  const handleScroll = () => {
    if (window.scrollY > 20) {
      siteHeader.classList.add('scrolled');
    } else {
      siteHeader.classList.remove('scrolled');
    }
  };

  window.addEventListener('scroll', handleScroll, { passive: true });
});
