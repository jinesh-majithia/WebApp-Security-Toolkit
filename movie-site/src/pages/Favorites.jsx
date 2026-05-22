
import { useFavorites } from '../context/FavoritesContext';
import MovieCard from '../components/MovieCard';
import { Link } from 'react-router-dom';
import './Favorites.css';

export default function Favorites() {
  const { favorites, favoritesCount } = useFavorites();

  return (
    <div className="favorites-page">
      <div className="favorites-header">
        <h1 className="favorites-title">Your Favorites</h1>
        <p className="favorites-subtitle">
          {favoritesCount === 0
            ? 'You haven\'t added any favorites yet.'
            : `You have ${favoritesCount} favorite movie${favoritesCount !== 1 ? 's' : ''}`}
        </p>
      </div>

      {favorites.length === 0 ? (
        <div className="favorites-empty">
          <div className="favorites-empty-icon">🎥</div>
          <p className="favorites-empty-text">
            Start exploring movies and add your favorites!
          </p>
          <Link to="/" className="favorites-empty-link">
            Browse Movies
          </Link>
        </div>
      ) : (
        <div className="favorites-grid">
          {favorites.map((movie) => (
            <MovieCard key={movie.id} movie={movie} />
          ))}
        </div>
      )}
    </div>
  );
}
