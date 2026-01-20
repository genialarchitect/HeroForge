import React from 'react';
import { Award, Download, Share2, ExternalLink, Calendar, Shield } from 'lucide-react';
import { Certificate, CertificateDetail, LearningPath } from '../../types/academy';

interface CertificateViewerProps {
  certificate: Certificate | CertificateDetail;
  path?: LearningPath | null;
  holderName?: string;
  onDownload?: () => void;
}

const CertificateViewer: React.FC<CertificateViewerProps> = ({
  certificate,
  path,
  holderName = 'Certificate Holder',
  onDownload,
}) => {
  // Get path info if available
  const pathData = 'path' in certificate && certificate.path ? certificate.path : path;

  // Format date
  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  // Share certificate
  const handleShare = async () => {
    const shareUrl = `${window.location.origin}/certificates/verify/${certificate.certificate_number}`;

    if (navigator.share) {
      try {
        await navigator.share({
          title: `HeroForge Academy Certificate - ${pathData?.title || 'Certificate'}`,
          text: `I earned my ${pathData?.title || 'HeroForge'} certificate!`,
          url: shareUrl,
        });
      } catch (err) {
        // User cancelled or share failed
        console.error('Share failed:', err);
      }
    } else {
      // Fallback: copy to clipboard
      try {
        await navigator.clipboard.writeText(shareUrl);
        alert('Certificate link copied to clipboard!');
      } catch (err) {
        console.error('Copy failed:', err);
      }
    }
  };

  // Open verification page
  const handleVerify = () => {
    window.open(`/certificates/verify/${certificate.certificate_number}`, '_blank');
  };

  // Get level colors
  const getLevelColors = (level?: string) => {
    switch (level) {
      case 'Beginner':
        return {
          bg: 'from-cyan-900/50 to-blue-900/50',
          border: 'border-cyan-600',
          accent: 'text-cyan-400',
        };
      case 'Professional':
        return {
          bg: 'from-purple-900/50 to-pink-900/50',
          border: 'border-purple-600',
          accent: 'text-purple-400',
        };
      case 'Expert':
        return {
          bg: 'from-orange-900/50 to-red-900/50',
          border: 'border-orange-600',
          accent: 'text-orange-400',
        };
      default:
        return {
          bg: 'from-gray-800 to-gray-900',
          border: 'border-gray-600',
          accent: 'text-gray-400',
        };
    }
  };

  const colors = getLevelColors(pathData?.level);

  return (
    <div className="certificate-viewer">
      {/* Certificate card */}
      <div
        className={`relative bg-gradient-to-br ${colors.bg} border-2 ${colors.border} rounded-2xl p-8 overflow-hidden`}
      >
        {/* Background pattern */}
        <div className="absolute inset-0 opacity-5">
          <div
            className="w-full h-full"
            style={{
              backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='1'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
            }}
          />
        </div>

        {/* Header */}
        <div className="relative text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-6 h-6 text-cyan-400 mr-2" />
            <span className="text-lg font-semibold text-gray-300">HeroForge Academy</span>
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Certificate of Completion</h1>
        </div>

        {/* Award icon */}
        <div className="relative flex justify-center mb-8">
          <div className={`w-24 h-24 rounded-full bg-gradient-to-br ${colors.bg} border-4 ${colors.border} flex items-center justify-center`}>
            <Award className={`w-12 h-12 ${colors.accent}`} />
          </div>
        </div>

        {/* Certificate details */}
        <div className="relative text-center mb-8">
          <p className="text-gray-400 mb-2">This certifies that</p>
          <h2 className="text-2xl font-bold text-white mb-4">{holderName}</h2>
          <p className="text-gray-400 mb-2">has successfully completed</p>
          <h3 className={`text-xl font-semibold ${colors.accent} mb-4`}>
            {pathData?.title || 'Learning Path'}
          </h3>
          {pathData?.certificate_name && (
            <p className="text-gray-300">
              and is hereby awarded the credential of
              <br />
              <span className="text-white font-semibold">{pathData.certificate_name}</span>
            </p>
          )}
        </div>

        {/* Certificate number and dates */}
        <div className="relative grid grid-cols-2 gap-4 text-sm mb-8">
          <div className="text-center p-4 bg-gray-900/50 rounded-lg">
            <p className="text-gray-500 mb-1">Certificate Number</p>
            <p className="text-white font-mono">{certificate.certificate_number}</p>
          </div>
          <div className="text-center p-4 bg-gray-900/50 rounded-lg">
            <p className="text-gray-500 mb-1">Issue Date</p>
            <p className="text-white">{formatDate(certificate.issued_at)}</p>
          </div>
        </div>

        {/* Expiration if applicable */}
        {certificate.expires_at && (
          <div className="relative text-center text-sm mb-8">
            <p className="text-gray-500">
              Valid until: <span className="text-gray-300">{formatDate(certificate.expires_at)}</span>
            </p>
          </div>
        )}

        {/* Footer */}
        <div className="relative flex items-center justify-center pt-6 border-t border-gray-700">
          <div className="text-center">
            <p className="text-xs text-gray-500 mb-1">Issued by</p>
            <p className="text-sm text-gray-300">Genial Architect Cybersecurity Research Associates</p>
          </div>
        </div>
      </div>

      {/* Action buttons */}
      <div className="flex flex-wrap gap-4 mt-6 justify-center">
        {onDownload && (
          <button
            onClick={onDownload}
            className="flex items-center px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white font-medium rounded-lg transition-colors"
          >
            <Download className="w-5 h-5 mr-2" />
            Download PDF
          </button>
        )}
        <button
          onClick={handleShare}
          className="flex items-center px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white font-medium rounded-lg transition-colors"
        >
          <Share2 className="w-5 h-5 mr-2" />
          Share
        </button>
        <button
          onClick={handleVerify}
          className="flex items-center px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white font-medium rounded-lg transition-colors"
        >
          <ExternalLink className="w-5 h-5 mr-2" />
          Verify
        </button>
      </div>
    </div>
  );
};

export default CertificateViewer;
