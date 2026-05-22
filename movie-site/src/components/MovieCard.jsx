
import { memo, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { getImageUrl } from '../services/api';
import { useFavorites } from '../context/FavoritesContext';
import './MovieCard.css';

function MovieCard({ movie }) {
  const { isFavorite, addFavorite, removeFavorite } = useFavorites();

  const isFav = isFavorite(movie.id);

  const handleFavoriteToggle = useCallback(
    (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (isFav) {
        removeFavorite(movie.id);
      } else {
        addFavorite(movie);
      }
    },
    [isFav, movie, addFavorite, removeFavorite]
  );

  const year = movie.release_date
    ? new Date(movie.release_date).getFullYear()
    : null;

  const rating = movie.vote_average
    ? Math.round(movie.vote_average * 10) / 10
    : null;

  const posterSrc = getImageUrl(movie.poster_path, 'w342');
  const posterAlt = `${movie.title} poster`;

  return (
    <article className="movie-card">
      <Link to={`/movie/${movie.id}`} className="movie-card-link">
        <div className="movie-card-poster-wrapper">
          {posterSrc ? (
            <img
              className="movie-card-poster"
              src={posterSrc}
              alt={posterAlt}
              loading="lazy"
              onError={(e) => {
                e.target.src = 'https://via.placeholder.com/342x513?text=No+Poster';
              }}
            />
          ) : (
            <div className="movie-card-no-poster">
              <span>🎬</span>
              <span>{movie.title}</span>
            </div>
          )}
          <button
            className={`movie-card-fav-btn ${isFav ? 'favorited' : ''}`}
            onClick={handleFavoriteToggle}
            aria-label={isFav ? `Remove ${movie.title} from favorites` : `Add ${movie.title} to favorites`}
            title={isFav ? 'Remove from favorites' : 'Add to favorites'}
          >
            {isFav ? '❤️' : '🤍'}
          </button>
        </div>
        <div className="movie-card-info">
          <h3 className="movie-card-title">{movie.title}</h3>
          <div className="movie-card-meta">
            {year && <span className="movie-card-year">{year}</span>}
            {rating !== null && (
              <span className="movie-card-rating">
                ⭐ {rating}
              </span>
            )}
          </div>
        </div>
      </Link>
    </article>
  );
}

export default memo(MovieCard);
