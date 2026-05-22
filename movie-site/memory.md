
# Memory Cache - Movie Site

## Project Setup
- **Scaffold:** Vite + React 19.1.1 (JSX)
- **Build:** Vite 7.1.2
- **Port:** 5173 (Vite default)
- **OS:** Windows (PowerShell)
- **Deps:** react, react-dom, react-router-dom, axios

## Architecture Decisions
- **Routing:** react-router-dom v7 with lazy loading + Suspense
- **API Layer:** Axios instance with interceptors in services/api.js
- **State Management:** React Context (FavoritesContext) for cross-page state
- **CSS Approach:** Vanilla CSS with global styles + component-specific CSS
- **Fetch Pattern:** Custom useFetch hook with cleanup, loading, error states
- **Search Optimization:** useDebounce hook (300ms default)
- **API Used:** TMDB (The Movie Database) — free tier, requires API key

## Folder Structure


## Key Environment Variables
- VITE_API_KEY: TMDB API key (set in .env)
- VITE_API_BASE_URL: https://api.themoviedb.org/3

## Build Optimizations
- Vendor chunking (react, react-dom, react-router-dom)
- Code-splitting via React.lazy
- Source maps disabled in production
- Manual chunks for cache optimization
