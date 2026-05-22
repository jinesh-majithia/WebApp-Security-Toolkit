
import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { movieService } from '../services/api';
import { useDebounce } from '../hooks/useDebounce';
import MovieCard from '../components/MovieCard';
import Spinner from '../components/Spinner';
import ErrorMessage from '../components/ErrorMessage';
import './SearchResults.css';

export default function SearchResults() {
  const [searchParams, setSearchParams] = useSearchParams();
  const query = searchParams.get('q') || '';
  const [page, setPage] = useState(1);
  const [movies, setMovies] = useState([]);
  const [totalPages, setTotalPages] = useState(0);
  const [totalResults, setTotalResults] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const debouncedQuery = useDebounce(query, 300);

  useEffect(() => {
    if (!debouncedQuery) {
      setMovies([]);
      setTotalPages(0);
      setTotalResults(0);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    movieService
      .search(debouncedQuery, page)
      .then((res) => {
        if (!cancelled) {
          setMovies(res.data.results || []);
          setTotalPages(res.data.total_pages || 0);
          setTotalResults(res.data.total_results || 0);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err.message || 'Search failed');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [debouncedQuery, page]);

  const handleSearch = (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const newQuery = formData.get('search').trim();
    if (newQuery) {
      setSearchParams({ q: newQuery });
      setPage(1);
    }
  };

  const handleNextPage = () => {
    if (page < totalPages) {
      setPage((p) => p + 1);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const handlePrevPage = () => {
    if (page > 1) {
      setPage((p) => p - 1);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  return (
    <div className="search-page">
      <div className="search-page-header">
        <h1 className="search-page-title">Search Movies</h1>
        <form className="search-page-form" onSubmit={handleSearch}>
          <input
            type="search"
            name="search"
            className="search-page-input"
            defaultValue={query}
            placeholder="Search for a movie..."
            aria-label="Search movies"
          />
          <button type="submit" className="search-page-btn">
            Search
          </button>
        </form>
      </div>

      {!query && (
        <p className="search-page-prompt">
          Enter a movie title above to start searching.
        </p>
      )}

      {query && loading && <Spinner text={`Searching for "${query}"...`} />}
      {query && error && <ErrorMessage message={error} />}

      {query && !loading && !error && movies.length === 0 && (
        <div className="search-page-no-results">
          <p>
            No results found for <strong>"{query}"</strong>
          </p>
          <p className="search-page-tip">
            Try adjusting your search terms or check for spelling errors.
          </p>
        </div>
      )}

      {query && !loading && !error && movies.length > 0 && (
        <>
          <p className="search-page-count">
            Found {totalResults} results for <strong>"{query}"</strong>
          </p>
          <div className="search-page-grid">
            {movies.map((movie) => (
              <MovieCard key={movie.id} movie={movie} />
            ))}
          </div>

          {totalPages > 1 && (
            <div className="search-page-pagination">
              <button
                className="search-page-pag-btn"
                onClick={handlePrevPage}
                disabled={page <= 1}
              >
                ← Previous
              </button>
              <span className="search-page-page-info">
                Page {page} of {totalPages}
              </span>
              <button
                className="search-page-pag-btn"
                onClick={handleNextPage}
                disabled={page >= totalPages}
              >
                Next →
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
