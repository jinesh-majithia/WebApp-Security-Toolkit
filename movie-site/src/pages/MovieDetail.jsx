
import { useParams, Link, useNavigate } from 'react-router-dom';
import { movieService, getImageUrl, getBackdropUrl } from '../services/api';
import { useFetch } from '../hooks/useFetch';
import { useFavorites } from '../context/FavoritesContext';
import MovieCard from '../components/MovieCard';
import Spinner from '../components/Spinner';
import ErrorMessage from '../components/ErrorMessage';
import './MovieDetail.css';

export default function MovieDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { isFavorite, addFavorite, removeFavorite } = useFavorites();

  const fetchMovie = () =>
    movieService.getDetails(id).then((res) => res.data);

  const fetchRecommendations = () =>
    movieService.getRecommendations(id).then((res) => res.data);

  const fetchCredits = () =>
    movieService.getCredits(id).then((res) => res.data);

  const {
    data: movie,
    loading: movieLoading,
    error: movieError,
    refetch: refetchMovie,
  } = useFetch(fetchMovie, [id]);

  const {
    data: recommendations,
    loading: recsLoading,
  } = useFetch(fetchRecommendations, [id]);

  const {
    data: credits,
  } = useFetch(fetchCredits, [id]);

  if (movieLoading) return <Spinner text="Loading movie details..." />;
  if (movieError) return <ErrorMessage message={movieError} onRetry={refetchMovie} />;
  if (!movie) return <ErrorMessage message="Movie not found" />;

  const isFav = isFavorite(movie.id);
  const backdrop = getBackdropUrl(movie.backdrop_path);
  const poster = getImageUrl(movie.poster_path, 'w342');
  const year = movie.release_date
    ? new Date(movie.release_date).getFullYear()
    : '';
  const rating = movie.vote_average
    ? Math.round(movie.vote_average * 10) / 10
    : null;
  const director =
    credits?.crew?.find((person) => person.job === 'Director')?.name || null;
  const cast = credits?.cast?.slice(0, 8) || [];
  const genres = movie.genres || [];
  const recMovies = recommendations?.results?.slice(0, 6) || [];

  const handleFavoriteToggle = () => {
    if (isFav) {
      removeFavorite(movie.id);
    } else {
      addFavorite(movie);
    }
  };

  return (
    <div className="movie-detail-page">
      {backdrop && (
        <div className="movie-detail-backdrop-wrapper">
          <img
            className="movie-detail-backdrop"
            src={backdrop}
            alt=""
            aria-hidden="true"
          />
          <div className="movie-detail-backdrop-overlay" />
        </div>
      )}

      <div className="movie-detail-content">
        <button className="movie-detail-back-btn" onClick={() => navigate(-1)}>
          ← Back
        </button>

        <div className="movie-detail-main">
          <div className="movie-detail-poster-wrapper">
            {poster ? (
              <img
                className="movie-detail-poster"
                src={poster}
                alt={`${movie.title} poster`}
              />
            ) : (
              <div className="movie-detail-no-poster">🎬</div>
            )}
          </div>

          <div className="movie-detail-info">
            <h1 className="movie-detail-title">
              {movie.title}
              {year && <span className="movie-detail-year"> ({year})</span>}
            </h1>

            {movie.tagline && (
              <p className="movie-detail-tagline">{movie.tagline}</p>
            )}

            <div className="movie-detail-meta">
              {rating !== null && (
                <span className="movie-detail-rating">
                  ⭐ {rating}/10
                </span>
              )}
              {movie.runtime > 0 && (
                <span className="movie-detail-runtime">
                  🕒 {Math.floor(movie.runtime / 60)}h {movie.runtime % 60}m
                </span>
              )}
              {movie.release_date && (
                <span className="movie-detail-date">
                  📅 {new Date(movie.release_date).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric',
                  })}
                </span>
              )}
            </div>

            {genres.length > 0 && (
              <div className="movie-detail-genres">
                {genres.map((genre) => (
                  <span key={genre.id} className="movie-detail-genre-tag">
                    {genre.name}
                  </span>
                ))}
              </div>
            )}

            <p className="movie-detail-overview">
              {movie.overview || 'No overview available.'}
            </p>

            {director && (
              <p className="movie-detail-director">
                <strong>Director:</strong> {director}
              </p>
            )}

            <button
              className={`movie-detail-fav-btn ${isFav ? 'favorited' : ''}`}
              onClick={handleFavoriteToggle}
            >
              {isFav ? '❤️ Remove from Favorites' : '🤍 Add to Favorites'}
            </button>
          </div>
        </div>

        {cast.length > 0 && (
          <section className="movie-detail-section">
            <h2 className="movie-detail-section-title">Cast</h2>
            <div className="movie-detail-cast">
              {cast.map((person) => (
                <div key={person.id} className="movie-detail-cast-member">
                  {person.profile_path ? (
                    <img
                      className="movie-detail-cast-photo"
                      src={getImageUrl(person.profile_path, 'w185')}
                      alt={person.name}
                      loading="lazy"
                    />
                  ) : (
                    <div className="movie-detail-cast-no-photo">
                      {person.name.charAt(0)}
                    </div>
                  )}
                  <p className="movie-detail-cast-name">{person.name}</p>
                  <p className="movie-detail-cast-character">
                    {person.character}
                  </p>
                </div>
              ))}
            </div>
          </section>
        )}

        {recMovies.length > 0 && (
          <section className="movie-detail-section">
            <h2 className="movie-detail-section-title">
              Recommended Movies
            </h2>
            <div className="movie-detail-recommendations">
              {recMovies.map((rec) => (
                <MovieCard key={rec.id} movie={rec} />
              ))}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
