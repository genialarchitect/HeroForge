import React, { useRef, useEffect, useState, useCallback } from 'react';
import { Play, Pause, Volume2, VolumeX, Maximize, SkipBack, SkipForward } from 'lucide-react';

interface VideoChapter {
  id: string;
  title: string;
  timestamp_seconds: number;
}

interface VideoPlayerProps {
  videoUrl: string;
  chapters?: VideoChapter[];
  initialTimestamp?: number;
  onProgress?: (timestamp: number, timeSpent: number) => void;
  onComplete?: () => void;
}

// Extract video ID and type from URL
function parseVideoUrl(url: string): { type: 'youtube' | 'vimeo' | 'unknown'; id: string | null } {
  // YouTube patterns
  const youtubeRegex = /(?:youtube\.com\/(?:watch\?v=|embed\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/;
  const youtubeMatch = url.match(youtubeRegex);
  if (youtubeMatch) {
    return { type: 'youtube', id: youtubeMatch[1] };
  }

  // Vimeo patterns
  const vimeoRegex = /(?:vimeo\.com\/(?:video\/)?|player\.vimeo\.com\/video\/)(\d+)/;
  const vimeoMatch = url.match(vimeoRegex);
  if (vimeoMatch) {
    return { type: 'vimeo', id: vimeoMatch[1] };
  }

  return { type: 'unknown', id: null };
}

const VideoPlayer: React.FC<VideoPlayerProps> = ({
  videoUrl,
  chapters = [],
  initialTimestamp = 0,
  onProgress,
  onComplete,
}) => {
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(initialTimestamp);
  const [duration, setDuration] = useState(0);
  const [isMuted, setIsMuted] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [timeSpent, setTimeSpent] = useState(0);
  const lastProgressUpdate = useRef<number>(Date.now());
  const progressInterval = useRef<ReturnType<typeof setInterval> | null>(null);

  const { type, id } = parseVideoUrl(videoUrl);

  // Get embed URL with timestamp
  const getEmbedUrl = useCallback(() => {
    if (type === 'youtube' && id) {
      const params = new URLSearchParams({
        enablejsapi: '1',
        start: Math.floor(initialTimestamp).toString(),
        rel: '0',
        modestbranding: '1',
      });
      return `https://www.youtube.com/embed/${id}?${params.toString()}`;
    }
    if (type === 'vimeo' && id) {
      const params = new URLSearchParams({
        autopause: '0',
        // Vimeo uses #t=XXs for timestamp
      });
      return `https://player.vimeo.com/video/${id}?${params.toString()}#t=${Math.floor(initialTimestamp)}s`;
    }
    return videoUrl;
  }, [type, id, initialTimestamp, videoUrl]);

  // Track time spent watching
  useEffect(() => {
    if (isPlaying) {
      progressInterval.current = setInterval(() => {
        setTimeSpent(prev => prev + 1);
        setCurrentTime(prev => prev + 1);
      }, 1000);
    } else {
      if (progressInterval.current) {
        clearInterval(progressInterval.current);
      }
    }

    return () => {
      if (progressInterval.current) {
        clearInterval(progressInterval.current);
      }
    };
  }, [isPlaying]);

  // Send progress updates periodically
  useEffect(() => {
    const now = Date.now();
    if (now - lastProgressUpdate.current >= 30000 && onProgress) {
      onProgress(currentTime, timeSpent);
      lastProgressUpdate.current = now;
    }
  }, [currentTime, timeSpent, onProgress]);

  // Check for completion
  useEffect(() => {
    if (duration > 0 && currentTime >= duration * 0.9 && onComplete) {
      onComplete();
    }
  }, [currentTime, duration, onComplete]);

  // Format time as MM:SS or HH:MM:SS
  const formatTime = (seconds: number) => {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    if (hrs > 0) {
      return `${hrs}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  // Jump to chapter
  const jumpToChapter = (timestamp: number) => {
    setCurrentTime(timestamp);
    // For YouTube, we'd need to use the iframe API
    // For now, just update our local state
    if (iframeRef.current && type === 'youtube' && id) {
      const newUrl = `https://www.youtube.com/embed/${id}?enablejsapi=1&start=${timestamp}&autoplay=1&rel=0&modestbranding=1`;
      iframeRef.current.src = newUrl;
      setIsPlaying(true);
    }
  };

  // Toggle fullscreen
  const toggleFullscreen = () => {
    const container = iframeRef.current?.parentElement?.parentElement;
    if (!container) return;

    if (!isFullscreen) {
      if (container.requestFullscreen) {
        container.requestFullscreen();
      }
    } else {
      if (document.exitFullscreen) {
        document.exitFullscreen();
      }
    }
    setIsFullscreen(!isFullscreen);
  };

  if (type === 'unknown') {
    return (
      <div className="bg-gray-800 rounded-lg p-8 text-center">
        <p className="text-gray-400">Unsupported video format</p>
        <a
          href={videoUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="text-cyan-400 hover:text-cyan-300 mt-2 inline-block"
        >
          Open video in new tab
        </a>
      </div>
    );
  }

  return (
    <div className="video-player-container">
      {/* Video Embed */}
      <div className="relative bg-black rounded-lg overflow-hidden aspect-video">
        <iframe
          ref={iframeRef}
          src={getEmbedUrl()}
          className="w-full h-full"
          allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; fullscreen"
          allowFullScreen
          title="Lesson Video"
        />
      </div>

      {/* Custom Controls Bar */}
      <div className="bg-gray-800 rounded-b-lg px-4 py-3 flex items-center justify-between">
        <div className="flex items-center space-x-4">
          {/* Play/Pause */}
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="text-gray-400 hover:text-white transition-colors"
            title={isPlaying ? 'Pause' : 'Play'}
          >
            {isPlaying ? <Pause className="w-5 h-5" /> : <Play className="w-5 h-5" />}
          </button>

          {/* Skip buttons */}
          <button
            onClick={() => jumpToChapter(Math.max(0, currentTime - 10))}
            className="text-gray-400 hover:text-white transition-colors"
            title="Back 10 seconds"
          >
            <SkipBack className="w-5 h-5" />
          </button>
          <button
            onClick={() => jumpToChapter(currentTime + 10)}
            className="text-gray-400 hover:text-white transition-colors"
            title="Forward 10 seconds"
          >
            <SkipForward className="w-5 h-5" />
          </button>

          {/* Time display */}
          <span className="text-sm text-gray-400">
            {formatTime(currentTime)} {duration > 0 && `/ ${formatTime(duration)}`}
          </span>
        </div>

        <div className="flex items-center space-x-4">
          {/* Mute toggle */}
          <button
            onClick={() => setIsMuted(!isMuted)}
            className="text-gray-400 hover:text-white transition-colors"
            title={isMuted ? 'Unmute' : 'Mute'}
          >
            {isMuted ? <VolumeX className="w-5 h-5" /> : <Volume2 className="w-5 h-5" />}
          </button>

          {/* Fullscreen */}
          <button
            onClick={toggleFullscreen}
            className="text-gray-400 hover:text-white transition-colors"
            title="Fullscreen"
          >
            <Maximize className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Chapter Markers */}
      {chapters.length > 0 && (
        <div className="mt-4">
          <h4 className="text-sm font-medium text-gray-300 mb-2">Chapters</h4>
          <div className="space-y-1">
            {chapters.map((chapter, index) => (
              <button
                key={chapter.id}
                onClick={() => jumpToChapter(chapter.timestamp_seconds)}
                className={`w-full text-left px-3 py-2 rounded text-sm transition-colors ${
                  currentTime >= chapter.timestamp_seconds &&
                  (index === chapters.length - 1 ||
                    currentTime < chapters[index + 1].timestamp_seconds)
                    ? 'bg-cyan-900/30 text-cyan-400'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                }`}
              >
                <span className="text-cyan-400 mr-2">{formatTime(chapter.timestamp_seconds)}</span>
                {chapter.title}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default VideoPlayer;
