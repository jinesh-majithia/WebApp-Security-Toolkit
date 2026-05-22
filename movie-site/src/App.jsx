
import { lazy, Suspense } from 'react';
import { Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Spinner from './components/Spinner';
import ErrorBoundary from './components/ErrorBoundary';
import './App.css';

// Lazy-loaded pages for code splitting
const Home = lazy(() => import('./pages/Home.jsx'));
const MovieDetail = lazy(() => import('./pages/MovieDetail.jsx'));
const SearchResults = lazy(() => import('./pages/SearchResults.jsx'));
const Favorites = lazy(() => import('./pages/Favorites.jsx'));
const NotFound = lazy(() => import('./pages/NotFound.jsx'));

function App() {
  return (
    <div className="app">
      <Navbar />
      <main className="app-main">
        <ErrorBoundary>
          <Suspense fallback={<Spinner text="Loading page..." />}>
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/movie/:id" element={<MovieDetail />} />
              <Route path="/search" element={<SearchResults />} />
              <Route path="/favorites" element={<Favorites />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </ErrorBoundary>
      </main>
    </div>
  );
}

export default App;
