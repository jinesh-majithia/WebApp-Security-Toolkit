
import { useState, useCallback } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useFavorites } from '../context/FavoritesContext';
import './Navbar.css';

export default function Navbar() {
  const [searchQuery, setSearchQuery] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const { favoritesCount } = useFavorites();

  const handleSearch = useCallback(
    (e) => {
      e.preventDefault();
      const trimmed = searchQuery.trim();
      if (trimmed) {
        navigate(`/search?q=${encodeURIComponent(trimmed)}`);
      }
    },
    [searchQuery, navigate]
  );

  const handleSearchChange = useCallback((e) => {
    setSearchQuery(e.target.value);
  }, []);

  return (
    <nav className="navbar">
      <div className="navbar-container">
        <Link to="/" className="navbar-brand">
          🎬 MovieSite
        </Link>

        <ul className="navbar-links">
          <li>
            <Link
              to="/"
              className={`navbar-link ${location.pathname === '/' ? 'active' : ''}`}
            >
              Home
            </Link>
          </li>
          <li>
            <Link
              to="/favorites"
              className={`navbar-link ${location.pathname === '/favorites' ? 'active' : ''}`}
            >
              Favorites
              {favoritesCount > 0 && (
                <span className="navbar-badge">{favoritesCount}</span>
              )}
            </Link>
          </li>
        </ul>

        <form className="navbar-search" onSubmit={handleSearch} role="search">
          <input
            type="search"
            className="navbar-search-input"
            placeholder="Search movies..."
            value={searchQuery}
            onChange={handleSearchChange}
            aria-label="Search movies"
          />
          <button type="submit" className="navbar-search-btn" aria-label="Submit search">
            🔍
          </button>
        </form>
      </div>
    </nav>
  );
}
