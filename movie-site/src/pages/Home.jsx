
import { useState } from 'react';
import { movieService } from '../services/api';
import { useFetch } from '../hooks/useFetch';
import MovieCard from '../components/MovieCard';
import Spinner from '../components/Spinner';
import ErrorMessage from '../components/ErrorMessage';
import './Home.css';

const TABS = [
  { key: 'popular', label: 'Popular', fetchFn: () => movieService.getPopular(1) },
  { key: 'trending', label: 'Trending', fetchFn: () => movieService.getTrending('day') },
  { key: 'top_rated', label: 'Top Rated', fetchFn: () => movieService.getTopRated(1) },
  { key: 'now_playing', label: 'Now Playing', fetchFn: () => movieService.getNowPlaying(1) },
  { key: 'upcoming', label: 'Upcoming', fetchFn: () => movieService.getUpcoming(1) },
];

export default function Home() {
  const [activeTab, setActiveTab] = useState(TABS[0].key);

  const activeTabConfig = TABS.find((t) => t.key === activeTab);
  const fetchFn = () => activeTabConfig.fetchFn().then((res) => res.data);

  const { data, loading, error, refetch } = useFetch(fetchFn, [activeTab]);

  const movies = data?.results || [];

  return (
    <div className="home-page">
      <section className="home-hero">
        <h1 className="home-hero-title">Discover Movies</h1>
        <p className="home-hero-subtitle">
          Explore popular, trending, and upcoming films
        </p>
      </section>

      <div className="home-tabs" role="tablist">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            className={`home-tab ${activeTab === tab.key ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.key)}
            role="tab"
            aria-selected={activeTab === tab.key}
            aria-controls="movies-panel"
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div id="movies-panel" role="tabpanel" className="home-movies-panel">
        {loading && <Spinner text="Loading movies..." />}
        {error && <ErrorMessage message={error} onRetry={refetch} />}
        {!loading && !error && movies.length === 0 && (
          <p className="home-empty">No movies found.</p>
        )}
        {!loading && !error && movies.length > 0 && (
          <div className="home-movie-grid">
            {movies.map((movie) => (
              <MovieCard key={movie.id} movie={movie} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
