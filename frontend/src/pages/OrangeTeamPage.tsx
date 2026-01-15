import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  GraduationCap,
  Trophy,
  Award,
  Target,
  Shield,
  BookOpen,
  Play,
  CheckCircle,
  XCircle,
  Clock,
  Star,
  Flame,
  Medal,
  Users,
  TrendingUp,
  Calendar,
  FileText,
  Download,
  RefreshCw,
  ChevronRight,
  Lock,
  Unlock,
  AlertTriangle,
  Zap,
  Crown,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import api from '../services/api';

// Types
interface Course {
  id: string;
  title: string;
  description: string;
  category: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  duration_minutes: number;
  modules_count: number;
  thumbnail_url?: string;
  is_mandatory: boolean;
  tags: string[];
  created_at: string;
}

interface Enrollment {
  id: string;
  course_id: string;
  course: Course;
  status: 'not_started' | 'in_progress' | 'completed';
  progress_percent: number;
  started_at?: string;
  completed_at?: string;
  current_module: number;
  total_modules: number;
}

interface Certificate {
  id: string;
  course_id: string;
  course_title: string;
  issued_at: string;
  expires_at?: string;
  certificate_url: string;
  score: number;
}

interface GamificationProfile {
  user_id: string;
  total_points: number;
  level: number;
  level_name: string;
  points_to_next_level: number;
  current_streak: number;
  longest_streak: number;
  rank: number;
  total_users: number;
  achievements_count: number;
}

interface LeaderboardEntry {
  rank: number;
  user_id: string;
  username: string;
  avatar_url?: string;
  total_points: number;
  level: number;
  level_name: string;
  badges_count: number;
}

interface Badge {
  id: string;
  name: string;
  description: string;
  icon: string;
  category: 'achievement' | 'milestone' | 'special' | 'streak';
  rarity: 'common' | 'uncommon' | 'rare' | 'epic' | 'legendary';
  earned_at: string;
  points_value: number;
}

interface Challenge {
  id: string;
  title: string;
  description: string;
  category: string;
  difficulty: 'easy' | 'medium' | 'hard';
  points: number;
  time_limit_minutes?: number;
  attempts_remaining: number;
  max_attempts: number;
  status: 'available' | 'attempted' | 'completed' | 'locked';
  expires_at?: string;
}

interface ChallengeAttemptResult {
  correct: boolean;
  points_earned: number;
  feedback: string;
  correct_answer?: string;
}

interface ComplianceStatus {
  user_id: string;
  overall_compliant: boolean;
  required_courses: ComplianceCourse[];
  upcoming_deadlines: ComplianceDeadline[];
  completion_rate: number;
}

interface ComplianceCourse {
  course_id: string;
  course_title: string;
  required_by: string;
  status: 'completed' | 'in_progress' | 'not_started' | 'overdue';
  due_date: string;
  completed_at?: string;
}

interface ComplianceDeadline {
  course_id: string;
  course_title: string;
  due_date: string;
  days_remaining: number;
}

// API Functions
const orangeTeamAPI = {
  // Courses
  getCourses: () => api.get<Course[]>('/orange-team/courses'),
  enrollInCourse: (courseId: string) => api.post(`/orange-team/courses/${courseId}/enroll`),
  getMyCourses: () => api.get<Enrollment[]>('/orange-team/my-courses'),

  // Gamification
  getGamificationProfile: () => api.get<GamificationProfile>('/orange-team/gamification/profile'),
  getLeaderboard: () => api.get<LeaderboardEntry[]>('/orange-team/gamification/leaderboard'),
  getMyBadges: () => api.get<Badge[]>('/orange-team/gamification/my-badges'),

  // Challenges
  getChallenges: () => api.get<Challenge[]>('/orange-team/challenges'),
  attemptChallenge: (challengeId: string, answer: string) =>
    api.post<ChallengeAttemptResult>(`/orange-team/challenges/${challengeId}/attempt`, { answer }),

  // Certificates
  getCertificates: () => api.get<Certificate[]>('/orange-team/certificates'),

  // Compliance
  getComplianceStatus: () => api.get<ComplianceStatus>('/orange-team/compliance/status'),
};

// Utility Components
const DifficultyBadge: React.FC<{ difficulty: string }> = ({ difficulty }) => {
  const colors: Record<string, string> = {
    beginner: 'bg-green-500/20 text-green-400 border-green-500/30',
    easy: 'bg-green-500/20 text-green-400 border-green-500/30',
    intermediate: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    advanced: 'bg-red-500/20 text-red-400 border-red-500/30',
    hard: 'bg-red-500/20 text-red-400 border-red-500/30',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded border capitalize ${colors[difficulty] || colors.beginner}`}>
      {difficulty}
    </span>
  );
};

const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const colors: Record<string, string> = {
    not_started: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
    in_progress: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
    completed: 'bg-green-500/20 text-green-400 border-green-500/30',
    overdue: 'bg-red-500/20 text-red-400 border-red-500/30',
    available: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    attempted: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    locked: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  };

  const labels: Record<string, string> = {
    not_started: 'Not Started',
    in_progress: 'In Progress',
    completed: 'Completed',
    overdue: 'Overdue',
    available: 'Available',
    attempted: 'Attempted',
    locked: 'Locked',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded border ${colors[status] || colors.not_started}`}>
      {labels[status] || status}
    </span>
  );
};

const RarityBadge: React.FC<{ rarity: string }> = ({ rarity }) => {
  const colors: Record<string, string> = {
    common: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
    uncommon: 'bg-green-500/20 text-green-400 border-green-500/30',
    rare: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    epic: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    legendary: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded border capitalize ${colors[rarity] || colors.common}`}>
      {rarity}
    </span>
  );
};

const ProgressBar: React.FC<{ percent: number; className?: string }> = ({ percent, className = '' }) => (
  <div className={`h-2 bg-gray-700 rounded-full overflow-hidden ${className}`}>
    <div
      className="h-full bg-cyan-500 rounded-full transition-all duration-300"
      style={{ width: `${Math.min(100, Math.max(0, percent))}%` }}
    />
  </div>
);

const StatsCard: React.FC<{
  label: string;
  value: string | number;
  icon: React.ReactNode;
  color: string;
  subtext?: string;
  onClick?: () => void;
}> = ({ label, value, icon, color, subtext, onClick }) => (
  <div
    onClick={onClick}
    className={`bg-gray-800 border border-gray-700 rounded-lg p-4 ${onClick ? 'cursor-pointer hover:border-cyan-500/50 hover:bg-gray-750 transition-all group' : ''}`}
  >
    <div className="flex items-center justify-between">
      <div className="flex-1">
        <p className="text-sm text-gray-400">{label}</p>
        <p className="text-2xl font-bold text-white">{value}</p>
        {subtext && <p className="text-xs text-gray-500">{subtext}</p>}
      </div>
      <div className="flex items-center gap-2">
        <div className={`p-3 rounded-lg ${color}`}>{icon}</div>
        {onClick && <ChevronRight className="w-5 h-5 text-gray-500 group-hover:text-cyan-400 transition-colors" />}
      </div>
    </div>
  </div>
);

// Tab Components
const MyTrainingTab: React.FC = () => {
  const { data: enrollments, isLoading } = useQuery({
    queryKey: ['orange-team-my-courses'],
    queryFn: () => orangeTeamAPI.getMyCourses().then(r => r.data),
  });

  const { data: certificates } = useQuery({
    queryKey: ['orange-team-certificates'],
    queryFn: () => orangeTeamAPI.getCertificates().then(r => r.data),
  });

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <RefreshCw className="h-8 w-8 animate-spin text-cyan-500" />
      </div>
    );
  }

  const inProgress = enrollments?.filter(e => e.status === 'in_progress') || [];
  const completed = enrollments?.filter(e => e.status === 'completed') || [];
  const notStarted = enrollments?.filter(e => e.status === 'not_started') || [];

  return (
    <div className="space-y-6">
      {/* Progress Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatsCard
          label="Enrolled Courses"
          value={enrollments?.length || 0}
          icon={<BookOpen className="h-5 w-5 text-cyan-400" />}
          color="bg-cyan-500/10"
        />
        <StatsCard
          label="In Progress"
          value={inProgress.length}
          icon={<Play className="h-5 w-5 text-yellow-400" />}
          color="bg-yellow-500/10"
        />
        <StatsCard
          label="Completed"
          value={completed.length}
          icon={<CheckCircle className="h-5 w-5 text-green-400" />}
          color="bg-green-500/10"
        />
        <StatsCard
          label="Certificates"
          value={certificates?.length || 0}
          icon={<Award className="h-5 w-5 text-purple-400" />}
          color="bg-purple-500/10"
        />
      </div>

      {/* In Progress Courses */}
      {inProgress.length > 0 && (
        <div>
          <h3 className="text-lg font-semibold text-white mb-4">Continue Learning</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {inProgress.map((enrollment) => (
              <div key={enrollment.id} className="bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-cyan-500/50 transition-colors">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <h4 className="font-semibold text-white">{enrollment.course.title}</h4>
                    <p className="text-sm text-gray-400">{enrollment.course.category}</p>
                  </div>
                  <DifficultyBadge difficulty={enrollment.course.difficulty} />
                </div>
                <div className="mb-3">
                  <div className="flex justify-between text-sm text-gray-400 mb-1">
                    <span>Module {enrollment.current_module} of {enrollment.total_modules}</span>
                    <span>{enrollment.progress_percent}%</span>
                  </div>
                  <ProgressBar percent={enrollment.progress_percent} />
                </div>
                <button className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors">
                  <Play className="h-4 w-4" />
                  Continue
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Not Started Courses */}
      {notStarted.length > 0 && (
        <div>
          <h3 className="text-lg font-semibold text-white mb-4">Ready to Start</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {notStarted.map((enrollment) => (
              <div key={enrollment.id} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <h4 className="font-semibold text-white">{enrollment.course.title}</h4>
                    <p className="text-sm text-gray-400">{enrollment.course.category}</p>
                  </div>
                  {enrollment.course.is_mandatory && (
                    <span className="px-2 py-1 text-xs font-medium rounded bg-red-500/20 text-red-400 border border-red-500/30">
                      Required
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-4 text-sm text-gray-400 mb-3">
                  <span className="flex items-center gap-1">
                    <Clock className="h-4 w-4" />
                    {enrollment.course.duration_minutes} min
                  </span>
                  <span className="flex items-center gap-1">
                    <FileText className="h-4 w-4" />
                    {enrollment.course.modules_count} modules
                  </span>
                </div>
                <button className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors">
                  <Play className="h-4 w-4" />
                  Start Course
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Completed Courses & Certificates */}
      {completed.length > 0 && (
        <div>
          <h3 className="text-lg font-semibold text-white mb-4">Completed Courses</h3>
          <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
            <table className="w-full">
              <thead className="bg-gray-900">
                <tr>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Course</th>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Completed</th>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Score</th>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Certificate</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {completed.map((enrollment) => {
                  const cert = certificates?.find(c => c.course_id === enrollment.course_id);
                  return (
                    <tr key={enrollment.id} className="hover:bg-gray-700/50">
                      <td className="px-4 py-3">
                        <div>
                          <p className="text-sm font-medium text-white">{enrollment.course.title}</p>
                          <p className="text-xs text-gray-400">{enrollment.course.category}</p>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-300">
                        {enrollment.completed_at ? new Date(enrollment.completed_at).toLocaleDateString() : '-'}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-300">
                        {cert ? `${cert.score}%` : '-'}
                      </td>
                      <td className="px-4 py-3">
                        {cert ? (
                          <button className="flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300">
                            <Download className="h-4 w-4" />
                            Download
                          </button>
                        ) : (
                          <span className="text-sm text-gray-500">Not available</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Empty State */}
      {(!enrollments || enrollments.length === 0) && (
        <div className="text-center py-12">
          <BookOpen className="h-12 w-12 text-gray-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">No Enrolled Courses</h3>
          <p className="text-gray-400 mb-4">Browse the course catalog to enroll in training courses</p>
        </div>
      )}
    </div>
  );
};

const CourseCatalogTab: React.FC = () => {
  const queryClient = useQueryClient();
  const [categoryFilter, setCategoryFilter] = useState<string>('all');

  const { data: courses, isLoading } = useQuery({
    queryKey: ['orange-team-courses'],
    queryFn: () => orangeTeamAPI.getCourses().then(r => r.data),
  });

  const { data: enrollments } = useQuery({
    queryKey: ['orange-team-my-courses'],
    queryFn: () => orangeTeamAPI.getMyCourses().then(r => r.data),
  });

  const enrollMutation = useMutation({
    mutationFn: (courseId: string) => orangeTeamAPI.enrollInCourse(courseId),
    onSuccess: () => {
      toast.success('Successfully enrolled in course');
      queryClient.invalidateQueries({ queryKey: ['orange-team-my-courses'] });
    },
    onError: () => toast.error('Failed to enroll in course'),
  });

  const enrolledCourseIds = new Set(enrollments?.map(e => e.course_id) || []);
  const categories = ['all', ...new Set(courses?.map(c => c.category) || [])];

  const filteredCourses = categoryFilter === 'all'
    ? courses
    : courses?.filter(c => c.category === categoryFilter);

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <RefreshCw className="h-8 w-8 animate-spin text-cyan-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Category Filter */}
      <div className="flex gap-2 flex-wrap">
        {categories.map((category) => (
          <button
            key={category}
            onClick={() => setCategoryFilter(category)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors capitalize ${
              categoryFilter === category
                ? 'bg-cyan-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            {category}
          </button>
        ))}
      </div>

      {/* Course Grid */}
      {filteredCourses?.length === 0 ? (
        <div className="text-center py-12">
          <GraduationCap className="h-12 w-12 text-gray-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">No Courses Available</h3>
          <p className="text-gray-400">Check back later for new training courses</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredCourses?.map((course) => {
            const isEnrolled = enrolledCourseIds.has(course.id);
            return (
              <div key={course.id} className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden hover:border-cyan-500/50 transition-colors">
                {course.thumbnail_url && (
                  <div className="h-32 bg-gray-700 bg-cover bg-center" style={{ backgroundImage: `url(${course.thumbnail_url})` }} />
                )}
                <div className="p-4">
                  <div className="flex items-start justify-between mb-2">
                    <h4 className="font-semibold text-white">{course.title}</h4>
                    {course.is_mandatory && (
                      <span className="px-2 py-0.5 text-xs font-medium rounded bg-red-500/20 text-red-400">
                        Required
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-gray-400 mb-3 line-clamp-2">{course.description}</p>
                  <div className="flex items-center gap-2 mb-3">
                    <DifficultyBadge difficulty={course.difficulty} />
                    <span className="text-xs text-gray-500">{course.category}</span>
                  </div>
                  <div className="flex items-center gap-4 text-sm text-gray-400 mb-4">
                    <span className="flex items-center gap-1">
                      <Clock className="h-4 w-4" />
                      {course.duration_minutes} min
                    </span>
                    <span className="flex items-center gap-1">
                      <FileText className="h-4 w-4" />
                      {course.modules_count} modules
                    </span>
                  </div>
                  {course.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-4">
                      {course.tags.slice(0, 3).map((tag) => (
                        <span key={tag} className="px-2 py-0.5 text-xs bg-gray-700 text-gray-300 rounded">
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                  <button
                    onClick={() => !isEnrolled && enrollMutation.mutate(course.id)}
                    disabled={isEnrolled || enrollMutation.isPending}
                    className={`w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                      isEnrolled
                        ? 'bg-green-600/20 text-green-400 cursor-default'
                        : 'bg-cyan-600 hover:bg-cyan-700 text-white'
                    }`}
                  >
                    {isEnrolled ? (
                      <>
                        <CheckCircle className="h-4 w-4" />
                        Enrolled
                      </>
                    ) : (
                      <>
                        <GraduationCap className="h-4 w-4" />
                        Enroll Now
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

const GamificationTab: React.FC = () => {
  const { data: profile, isLoading: loadingProfile } = useQuery({
    queryKey: ['orange-team-gamification-profile'],
    queryFn: () => orangeTeamAPI.getGamificationProfile().then(r => r.data),
  });

  const { data: leaderboard, isLoading: loadingLeaderboard } = useQuery({
    queryKey: ['orange-team-leaderboard'],
    queryFn: () => orangeTeamAPI.getLeaderboard().then(r => r.data),
  });

  const { data: badges, isLoading: loadingBadges } = useQuery({
    queryKey: ['orange-team-my-badges'],
    queryFn: () => orangeTeamAPI.getMyBadges().then(r => r.data),
  });

  const isLoading = loadingProfile || loadingLeaderboard || loadingBadges;

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <RefreshCw className="h-8 w-8 animate-spin text-cyan-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Profile Stats */}
      {profile && (
        <>
          <div className="bg-gradient-to-r from-cyan-900/50 to-purple-900/50 border border-cyan-500/30 rounded-lg p-6">
            <div className="flex items-center gap-6">
              <div className="flex-shrink-0">
                <div className="w-20 h-20 bg-gradient-to-br from-cyan-500 to-purple-500 rounded-full flex items-center justify-center">
                  <Crown className="h-10 w-10 text-white" />
                </div>
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <h3 className="text-2xl font-bold text-white">Level {profile.level}</h3>
                  <span className="px-3 py-1 bg-cyan-500/20 text-cyan-400 rounded-full text-sm font-medium">
                    {profile.level_name}
                  </span>
                </div>
                <div className="flex items-center gap-6 text-sm text-gray-400">
                  <span className="flex items-center gap-1">
                    <Star className="h-4 w-4 text-yellow-400" />
                    {profile.total_points.toLocaleString()} points
                  </span>
                  <span className="flex items-center gap-1">
                    <TrendingUp className="h-4 w-4 text-green-400" />
                    Rank #{profile.rank} of {profile.total_users}
                  </span>
                  <span className="flex items-center gap-1">
                    <Flame className="h-4 w-4 text-orange-400" />
                    {profile.current_streak} day streak
                  </span>
                </div>
                <div className="mt-4">
                  <div className="flex justify-between text-sm text-gray-400 mb-1">
                    <span>Progress to Level {profile.level + 1}</span>
                    <span>{profile.points_to_next_level} points needed</span>
                  </div>
                  <ProgressBar percent={75} />
                </div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <StatsCard
              label="Total Points"
              value={profile.total_points.toLocaleString()}
              icon={<Star className="h-5 w-5 text-yellow-400" />}
              color="bg-yellow-500/10"
            />
            <StatsCard
              label="Current Rank"
              value={`#${profile.rank}`}
              icon={<Trophy className="h-5 w-5 text-cyan-400" />}
              color="bg-cyan-500/10"
              subtext={`of ${profile.total_users} users`}
            />
            <StatsCard
              label="Current Streak"
              value={profile.current_streak}
              icon={<Flame className="h-5 w-5 text-orange-400" />}
              color="bg-orange-500/10"
              subtext={`Best: ${profile.longest_streak} days`}
            />
            <StatsCard
              label="Badges Earned"
              value={profile.achievements_count}
              icon={<Medal className="h-5 w-5 text-purple-400" />}
              color="bg-purple-500/10"
            />
          </div>
        </>
      )}

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Leaderboard */}
        <div>
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Trophy className="h-5 w-5 text-yellow-400" />
            Leaderboard
          </h3>
          <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
            <div className="divide-y divide-gray-700">
              {leaderboard?.slice(0, 10).map((entry, index) => (
                <div
                  key={entry.user_id}
                  className={`flex items-center gap-4 p-4 ${
                    entry.user_id === profile?.user_id ? 'bg-cyan-900/20' : 'hover:bg-gray-700/50'
                  }`}
                >
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center font-bold text-sm ${
                    index === 0 ? 'bg-yellow-500 text-yellow-900' :
                    index === 1 ? 'bg-gray-400 text-gray-900' :
                    index === 2 ? 'bg-orange-600 text-orange-100' :
                    'bg-gray-700 text-gray-300'
                  }`}>
                    {entry.rank}
                  </div>
                  <div className="flex-1">
                    <p className="font-medium text-white">{entry.username}</p>
                    <p className="text-xs text-gray-400">{entry.level_name}</p>
                  </div>
                  <div className="text-right">
                    <p className="font-semibold text-white">{entry.total_points.toLocaleString()}</p>
                    <p className="text-xs text-gray-400">{entry.badges_count} badges</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Badges */}
        <div>
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Medal className="h-5 w-5 text-purple-400" />
            Your Badges
          </h3>
          {badges?.length === 0 ? (
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 text-center">
              <Award className="h-12 w-12 text-gray-500 mx-auto mb-4" />
              <h4 className="text-lg font-medium text-white mb-2">No Badges Yet</h4>
              <p className="text-gray-400">Complete courses and challenges to earn badges</p>
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-4">
              {badges?.map((badge) => (
                <div key={badge.id} className="bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-purple-500/50 transition-colors">
                  <div className="flex items-start gap-3">
                    <div className="w-12 h-12 bg-purple-900/50 rounded-lg flex items-center justify-center text-2xl">
                      {badge.icon}
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="font-medium text-white truncate">{badge.name}</h4>
                      <p className="text-xs text-gray-400 line-clamp-2">{badge.description}</p>
                      <div className="flex items-center gap-2 mt-2">
                        <RarityBadge rarity={badge.rarity} />
                        <span className="text-xs text-gray-500">+{badge.points_value} pts</span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const ChallengesTab: React.FC = () => {
  const queryClient = useQueryClient();
  const [selectedChallenge, setSelectedChallenge] = useState<Challenge | null>(null);
  const [answer, setAnswer] = useState('');
  const [attemptResult, setAttemptResult] = useState<ChallengeAttemptResult | null>(null);

  const { data: challenges, isLoading } = useQuery({
    queryKey: ['orange-team-challenges'],
    queryFn: () => orangeTeamAPI.getChallenges().then(r => r.data),
  });

  const attemptMutation = useMutation({
    mutationFn: ({ challengeId, answer }: { challengeId: string; answer: string }) =>
      orangeTeamAPI.attemptChallenge(challengeId, answer).then(r => r.data),
    onSuccess: (result) => {
      setAttemptResult(result);
      if (result.correct) {
        toast.success(`Correct! You earned ${result.points_earned} points!`);
      } else {
        toast.error('Incorrect answer. Try again!');
      }
      queryClient.invalidateQueries({ queryKey: ['orange-team-challenges'] });
      queryClient.invalidateQueries({ queryKey: ['orange-team-gamification-profile'] });
    },
    onError: () => toast.error('Failed to submit answer'),
  });

  const handleSubmit = () => {
    if (selectedChallenge && answer.trim()) {
      attemptMutation.mutate({ challengeId: selectedChallenge.id, answer: answer.trim() });
    }
  };

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <RefreshCw className="h-8 w-8 animate-spin text-cyan-500" />
      </div>
    );
  }

  const available = challenges?.filter(c => c.status === 'available') || [];
  const attempted = challenges?.filter(c => c.status === 'attempted') || [];
  const completed = challenges?.filter(c => c.status === 'completed') || [];

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatsCard
          label="Available"
          value={available.length}
          icon={<Target className="h-5 w-5 text-cyan-400" />}
          color="bg-cyan-500/10"
        />
        <StatsCard
          label="Attempted"
          value={attempted.length}
          icon={<Zap className="h-5 w-5 text-yellow-400" />}
          color="bg-yellow-500/10"
        />
        <StatsCard
          label="Completed"
          value={completed.length}
          icon={<CheckCircle className="h-5 w-5 text-green-400" />}
          color="bg-green-500/10"
        />
        <StatsCard
          label="Total Points Possible"
          value={challenges?.reduce((acc, c) => acc + c.points, 0) || 0}
          icon={<Star className="h-5 w-5 text-purple-400" />}
          color="bg-purple-500/10"
        />
      </div>

      {/* Challenge Grid */}
      {challenges?.length === 0 ? (
        <div className="text-center py-12">
          <Target className="h-12 w-12 text-gray-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">No Challenges Available</h3>
          <p className="text-gray-400">Check back later for new security challenges</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {challenges?.map((challenge) => (
            <div
              key={challenge.id}
              className={`bg-gray-800 border rounded-lg p-4 transition-colors ${
                challenge.status === 'locked'
                  ? 'border-gray-700 opacity-60'
                  : challenge.status === 'completed'
                  ? 'border-green-500/50'
                  : 'border-gray-700 hover:border-cyan-500/50'
              }`}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex-1">
                  <h4 className="font-semibold text-white flex items-center gap-2">
                    {challenge.status === 'locked' && <Lock className="h-4 w-4 text-gray-500" />}
                    {challenge.status === 'completed' && <CheckCircle className="h-4 w-4 text-green-400" />}
                    {challenge.title}
                  </h4>
                  <p className="text-sm text-gray-400">{challenge.category}</p>
                </div>
                <div className="flex items-center gap-2">
                  <DifficultyBadge difficulty={challenge.difficulty} />
                </div>
              </div>
              <p className="text-sm text-gray-400 mb-3 line-clamp-2">{challenge.description}</p>
              <div className="flex items-center gap-4 text-sm text-gray-400 mb-4">
                <span className="flex items-center gap-1">
                  <Star className="h-4 w-4 text-yellow-400" />
                  {challenge.points} pts
                </span>
                {challenge.time_limit_minutes && (
                  <span className="flex items-center gap-1">
                    <Clock className="h-4 w-4" />
                    {challenge.time_limit_minutes} min
                  </span>
                )}
                <span className="flex items-center gap-1">
                  <Target className="h-4 w-4" />
                  {challenge.attempts_remaining}/{challenge.max_attempts}
                </span>
              </div>
              {challenge.expires_at && (
                <div className="text-xs text-yellow-400 mb-3 flex items-center gap-1">
                  <AlertTriangle className="h-3 w-3" />
                  Expires: {new Date(challenge.expires_at).toLocaleDateString()}
                </div>
              )}
              <button
                onClick={() => {
                  if (challenge.status === 'available' || challenge.status === 'attempted') {
                    setSelectedChallenge(challenge);
                    setAnswer('');
                    setAttemptResult(null);
                  }
                }}
                disabled={challenge.status === 'locked' || challenge.status === 'completed' || challenge.attempts_remaining === 0}
                className={`w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                  challenge.status === 'completed'
                    ? 'bg-green-600/20 text-green-400 cursor-default'
                    : challenge.status === 'locked' || challenge.attempts_remaining === 0
                    ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                    : 'bg-cyan-600 hover:bg-cyan-700 text-white'
                }`}
              >
                {challenge.status === 'completed' ? (
                  <>
                    <CheckCircle className="h-4 w-4" />
                    Completed
                  </>
                ) : challenge.status === 'locked' ? (
                  <>
                    <Lock className="h-4 w-4" />
                    Locked
                  </>
                ) : challenge.attempts_remaining === 0 ? (
                  <>
                    <XCircle className="h-4 w-4" />
                    No Attempts Left
                  </>
                ) : (
                  <>
                    <Zap className="h-4 w-4" />
                    Attempt Challenge
                  </>
                )}
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Challenge Modal */}
      {selectedChallenge && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-lg w-full max-w-lg">
            <div className="p-6 border-b border-gray-700">
              <div className="flex items-center justify-between">
                <h3 className="text-xl font-semibold text-white">{selectedChallenge.title}</h3>
                <button
                  onClick={() => setSelectedChallenge(null)}
                  className="p-2 hover:bg-gray-700 rounded-lg"
                >
                  <XCircle className="h-5 w-5 text-gray-400" />
                </button>
              </div>
            </div>
            <div className="p-6">
              <div className="flex items-center gap-4 mb-4">
                <DifficultyBadge difficulty={selectedChallenge.difficulty} />
                <span className="text-sm text-gray-400">{selectedChallenge.category}</span>
                <span className="text-sm text-yellow-400 flex items-center gap-1">
                  <Star className="h-4 w-4" />
                  {selectedChallenge.points} pts
                </span>
              </div>
              <p className="text-gray-300 mb-6">{selectedChallenge.description}</p>

              {attemptResult ? (
                <div className={`p-4 rounded-lg mb-6 ${
                  attemptResult.correct ? 'bg-green-900/50 border border-green-500/50' : 'bg-red-900/50 border border-red-500/50'
                }`}>
                  <div className="flex items-center gap-2 mb-2">
                    {attemptResult.correct ? (
                      <CheckCircle className="h-5 w-5 text-green-400" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-400" />
                    )}
                    <span className={`font-medium ${attemptResult.correct ? 'text-green-400' : 'text-red-400'}`}>
                      {attemptResult.correct ? 'Correct!' : 'Incorrect'}
                    </span>
                  </div>
                  <p className="text-sm text-gray-300">{attemptResult.feedback}</p>
                  {attemptResult.points_earned > 0 && (
                    <p className="text-sm text-yellow-400 mt-2">+{attemptResult.points_earned} points earned!</p>
                  )}
                </div>
              ) : (
                <div className="mb-6">
                  <label className="block text-sm font-medium text-gray-300 mb-2">Your Answer</label>
                  <textarea
                    value={answer}
                    onChange={(e) => setAnswer(e.target.value)}
                    placeholder="Enter your answer..."
                    rows={4}
                    className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              )}

              <div className="flex items-center justify-between text-sm text-gray-400 mb-6">
                <span>Attempts remaining: {selectedChallenge.attempts_remaining}/{selectedChallenge.max_attempts}</span>
                {selectedChallenge.time_limit_minutes && (
                  <span>Time limit: {selectedChallenge.time_limit_minutes} minutes</span>
                )}
              </div>

              <div className="flex gap-3">
                <button
                  onClick={() => setSelectedChallenge(null)}
                  className="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
                >
                  Close
                </button>
                {!attemptResult && (
                  <button
                    onClick={handleSubmit}
                    disabled={!answer.trim() || attemptMutation.isPending}
                    className="flex-1 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {attemptMutation.isPending ? 'Submitting...' : 'Submit Answer'}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const ComplianceTab: React.FC = () => {
  const { data: status, isLoading } = useQuery({
    queryKey: ['orange-team-compliance-status'],
    queryFn: () => orangeTeamAPI.getComplianceStatus().then(r => r.data),
  });

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <RefreshCw className="h-8 w-8 animate-spin text-cyan-500" />
      </div>
    );
  }

  const overdue = status?.required_courses.filter(c => c.status === 'overdue') || [];
  const inProgress = status?.required_courses.filter(c => c.status === 'in_progress') || [];
  const notStarted = status?.required_courses.filter(c => c.status === 'not_started') || [];
  const completed = status?.required_courses.filter(c => c.status === 'completed') || [];

  return (
    <div className="space-y-6">
      {/* Compliance Status Banner */}
      {status && (
        <div className={`p-6 rounded-lg border ${
          status.overall_compliant
            ? 'bg-green-900/20 border-green-500/50'
            : 'bg-red-900/20 border-red-500/50'
        }`}>
          <div className="flex items-center gap-4">
            <div className={`p-4 rounded-full ${
              status.overall_compliant ? 'bg-green-500/20' : 'bg-red-500/20'
            }`}>
              {status.overall_compliant ? (
                <CheckCircle className="h-8 w-8 text-green-400" />
              ) : (
                <AlertTriangle className="h-8 w-8 text-red-400" />
              )}
            </div>
            <div>
              <h3 className={`text-xl font-bold ${
                status.overall_compliant ? 'text-green-400' : 'text-red-400'
              }`}>
                {status.overall_compliant ? 'Compliant' : 'Non-Compliant'}
              </h3>
              <p className="text-gray-400">
                {status.overall_compliant
                  ? 'You have completed all required training'
                  : `You have ${overdue.length + notStarted.length + inProgress.length} outstanding training requirements`}
              </p>
            </div>
            <div className="ml-auto text-right">
              <p className="text-3xl font-bold text-white">{Math.round(status.completion_rate)}%</p>
              <p className="text-sm text-gray-400">Completion Rate</p>
            </div>
          </div>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatsCard
          label="Required Courses"
          value={status?.required_courses.length || 0}
          icon={<BookOpen className="h-5 w-5 text-cyan-400" />}
          color="bg-cyan-500/10"
        />
        <StatsCard
          label="Completed"
          value={completed.length}
          icon={<CheckCircle className="h-5 w-5 text-green-400" />}
          color="bg-green-500/10"
        />
        <StatsCard
          label="In Progress"
          value={inProgress.length}
          icon={<Play className="h-5 w-5 text-yellow-400" />}
          color="bg-yellow-500/10"
        />
        <StatsCard
          label="Overdue"
          value={overdue.length}
          icon={<AlertTriangle className="h-5 w-5 text-red-400" />}
          color="bg-red-500/10"
        />
      </div>

      {/* Upcoming Deadlines */}
      {status?.upcoming_deadlines && status.upcoming_deadlines.length > 0 && (
        <div>
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Calendar className="h-5 w-5 text-yellow-400" />
            Upcoming Deadlines
          </h3>
          <div className="bg-yellow-900/20 border border-yellow-500/50 rounded-lg p-4">
            <div className="space-y-3">
              {status.upcoming_deadlines.map((deadline) => (
                <div key={deadline.course_id} className="flex items-center justify-between">
                  <div>
                    <p className="font-medium text-white">{deadline.course_title}</p>
                    <p className="text-sm text-gray-400">Due: {new Date(deadline.due_date).toLocaleDateString()}</p>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                    deadline.days_remaining <= 3
                      ? 'bg-red-500/20 text-red-400'
                      : deadline.days_remaining <= 7
                      ? 'bg-yellow-500/20 text-yellow-400'
                      : 'bg-blue-500/20 text-blue-400'
                  }`}>
                    {deadline.days_remaining} days left
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Overdue Courses */}
      {overdue.length > 0 && (
        <div>
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-red-400" />
            Overdue Training
          </h3>
          <div className="bg-red-900/20 border border-red-500/50 rounded-lg overflow-hidden">
            <table className="w-full">
              <thead className="bg-red-900/30">
                <tr>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-300">Course</th>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-300">Required By</th>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-300">Due Date</th>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-300">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-red-500/20">
                {overdue.map((course) => (
                  <tr key={course.course_id}>
                    <td className="px-4 py-3 text-sm text-white font-medium">{course.course_title}</td>
                    <td className="px-4 py-3 text-sm text-gray-300">{course.required_by}</td>
                    <td className="px-4 py-3 text-sm text-red-400">{new Date(course.due_date).toLocaleDateString()}</td>
                    <td className="px-4 py-3">
                      <button className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-sm rounded-lg transition-colors">
                        Start Now
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* All Required Courses */}
      <div>
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Shield className="h-5 w-5 text-cyan-400" />
          All Required Training
        </h3>
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-900">
              <tr>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Course</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Required By</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Due Date</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Status</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Completed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {status?.required_courses.map((course) => (
                <tr key={course.course_id} className="hover:bg-gray-700/50">
                  <td className="px-4 py-3 text-sm text-white font-medium">{course.course_title}</td>
                  <td className="px-4 py-3 text-sm text-gray-300">{course.required_by}</td>
                  <td className="px-4 py-3 text-sm text-gray-300">{new Date(course.due_date).toLocaleDateString()}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={course.status} />
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-300">
                    {course.completed_at ? new Date(course.completed_at).toLocaleDateString() : '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// Main Page Component
const OrangeTeamPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'my-training' | 'catalog' | 'gamification' | 'challenges' | 'compliance'>('my-training');

  const tabs = [
    { id: 'my-training' as const, label: 'My Training', icon: <BookOpen className="h-4 w-4" /> },
    { id: 'catalog' as const, label: 'Course Catalog', icon: <GraduationCap className="h-4 w-4" /> },
    { id: 'gamification' as const, label: 'Gamification', icon: <Trophy className="h-4 w-4" /> },
    { id: 'challenges' as const, label: 'Challenges', icon: <Target className="h-4 w-4" /> },
    { id: 'compliance' as const, label: 'Compliance', icon: <Shield className="h-4 w-4" /> },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="p-3 bg-orange-500/20 rounded-lg">
            <GraduationCap className="h-8 w-8 text-orange-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Security Awareness & Training</h1>
            <p className="text-gray-400">Orange Team - Build your security knowledge and skills</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 border-b border-gray-700 pb-2 overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
                activeTab === tab.id
                  ? 'bg-cyan-600 text-white'
                  : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'my-training' && <MyTrainingTab />}
        {activeTab === 'catalog' && <CourseCatalogTab />}
        {activeTab === 'gamification' && <GamificationTab />}
        {activeTab === 'challenges' && <ChallengesTab />}
        {activeTab === 'compliance' && <ComplianceTab />}
      </div>
    </Layout>
  );
};

export default OrangeTeamPage;
