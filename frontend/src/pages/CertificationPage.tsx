import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Award,
  Clock,
  CheckCircle,
  BookOpen,
  Users,
  Trophy,
  Star,
  ArrowRight,
  Play,
  Lock,
  Shield,
  Target,
  Zap,
  FileCheck,
  BadgeCheck,
  Calendar,
  Download,
  Share2,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  Timer,
  X,
} from 'lucide-react';

interface Certification {
  id: string;
  name: string;
  shortName: string;
  level: 'entry' | 'professional' | 'expert';
  price: number;
  duration: string;
  examDuration: number; // minutes
  passingScore: number;
  validity: string;
  description: string;
  topics: string[];
  prerequisites: string[];
  benefits: string[];
  examFormat: {
    multipleChoice: number;
    practical: number;
    scenario: number;
  };
  color: string;
  icon: React.ReactNode;
}

interface UserCertification {
  certificationId: string;
  earnedDate: string;
  expiryDate: string;
  credentialId: string;
  score: number;
  status: 'active' | 'expired' | 'pending_renewal';
}

interface ExamQuestion {
  id: string;
  type: 'multiple_choice' | 'multiple_select' | 'scenario';
  question: string;
  options: string[];
  correctAnswers: number[];
  explanation: string;
  points: number;
  category: string;
}

const certifications: Certification[] = [
  {
    id: 'hca',
    name: 'HeroForge Certified Analyst',
    shortName: 'HCA',
    level: 'entry',
    price: 199,
    duration: '2-4 weeks prep',
    examDuration: 90,
    passingScore: 70,
    validity: '2 years',
    description: 'Entry-level certification validating foundational security assessment skills using HeroForge.',
    topics: [
      'Network scanning fundamentals',
      'Vulnerability assessment basics',
      'Understanding CVSS scores',
      'Basic report generation',
      'Asset discovery techniques',
      'Common vulnerability types',
      'Scan configuration',
      'Result interpretation',
    ],
    prerequisites: [
      'Basic networking knowledge (TCP/IP, DNS)',
      'Familiarity with common security concepts',
      'Completed HeroForge Academy Beginner Path (recommended)',
    ],
    benefits: [
      'Industry-recognized credential',
      'Digital badge for LinkedIn',
      'Access to certified community',
      'Priority support access',
      'Certification verification portal listing',
    ],
    examFormat: {
      multipleChoice: 50,
      practical: 10,
      scenario: 5,
    },
    color: 'from-blue-500 to-cyan-500',
    icon: <Shield className="w-8 h-8" />,
  },
  {
    id: 'hcp',
    name: 'HeroForge Certified Professional',
    shortName: 'HCP',
    level: 'professional',
    price: 499,
    duration: '4-8 weeks prep',
    examDuration: 180,
    passingScore: 75,
    validity: '2 years',
    description: 'Professional certification for security practitioners demonstrating advanced assessment and reporting skills.',
    topics: [
      'Advanced enumeration techniques',
      'Web application security testing',
      'Cloud security assessment (AWS/Azure/GCP)',
      'Compliance framework mapping',
      'Professional report writing',
      'Vulnerability prioritization',
      'Remediation guidance',
      'API security testing',
      'Container security basics',
      'Integration with SIEM/ticketing',
    ],
    prerequisites: [
      'HCA certification or equivalent experience',
      '1+ years security assessment experience',
      'Completed HeroForge Academy Professional Path (recommended)',
    ],
    benefits: [
      'Advanced credential recognition',
      'Featured in certified professionals directory',
      'Access to beta features',
      'Exclusive webinars and training',
      'Employer verification portal',
      '20% discount on HCE exam',
    ],
    examFormat: {
      multipleChoice: 40,
      practical: 25,
      scenario: 10,
    },
    color: 'from-purple-500 to-pink-500',
    icon: <Target className="w-8 h-8" />,
  },
  {
    id: 'hce',
    name: 'HeroForge Certified Expert',
    shortName: 'HCE',
    level: 'expert',
    price: 999,
    duration: '8-12 weeks prep',
    examDuration: 480,
    passingScore: 80,
    validity: '2 years',
    description: 'Expert-level certification for senior security professionals demonstrating mastery of advanced security operations.',
    topics: [
      'Red team operations',
      'Purple team exercises',
      'Advanced threat hunting',
      'Building security programs',
      'Enterprise architecture assessment',
      'Custom scan development',
      'Automation and orchestration',
      'Incident response integration',
      'Advanced compliance (FedRAMP, SOC 2)',
      'Security metrics and KPIs',
      'Team leadership',
      'Client engagement management',
    ],
    prerequisites: [
      'HCP certification',
      '3+ years security assessment experience',
      'Experience leading security assessments',
      'Completed HeroForge Academy Expert Path (recommended)',
    ],
    benefits: [
      'Highest-level credential',
      'Expert directory listing with profile',
      'Speaking opportunities at HeroForge events',
      'Input on product roadmap',
      'Free annual subscription ($1,188 value)',
      'Invitation to Expert Advisory Board',
    ],
    examFormat: {
      multipleChoice: 30,
      practical: 40,
      scenario: 20,
    },
    color: 'from-amber-500 to-orange-500',
    icon: <Trophy className="w-8 h-8" />,
  },
];

const sampleQuestions: ExamQuestion[] = [
  {
    id: '1',
    type: 'multiple_choice',
    question: 'What is the default port for HTTPS?',
    options: ['80', '443', '8080', '8443'],
    correctAnswers: [1],
    explanation: 'HTTPS uses port 443 by default. Port 80 is for HTTP, while 8080 and 8443 are common alternative ports.',
    points: 1,
    category: 'Networking Fundamentals',
  },
  {
    id: '2',
    type: 'multiple_select',
    question: 'Which of the following are valid CVSS v3.1 severity ratings? (Select all that apply)',
    options: ['None', 'Low', 'Medium', 'High', 'Critical', 'Severe'],
    correctAnswers: [0, 1, 2, 3, 4],
    explanation: 'CVSS v3.1 has five severity ratings: None (0.0), Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), and Critical (9.0-10.0). "Severe" is not a valid CVSS rating.',
    points: 2,
    category: 'Vulnerability Assessment',
  },
  {
    id: '3',
    type: 'scenario',
    question: 'You discover a critical vulnerability (CVE-2024-1234) on a production database server. The vulnerability has a CVSS score of 9.8 and a public exploit is available. What should be your FIRST action?',
    options: [
      'Immediately patch the system',
      'Document the finding and notify the client/stakeholder',
      'Attempt to exploit the vulnerability to confirm it',
      'Ignore it since production systems are sensitive',
    ],
    correctAnswers: [1],
    explanation: 'The first action should always be to document and notify. Patching without approval could cause outages, exploitation without authorization is unethical/illegal, and ignoring critical findings is negligent.',
    points: 3,
    category: 'Professional Conduct',
  },
];

const userCertifications: UserCertification[] = [
  {
    certificationId: 'hca',
    earnedDate: '2025-06-15',
    expiryDate: '2027-06-15',
    credentialId: 'HCA-2025-78432',
    score: 85,
    status: 'active',
  },
];

export default function CertificationPage() {
  const [selectedCert, setSelectedCert] = useState<Certification | null>(null);
  const [showExamModal, setShowExamModal] = useState(false);
  const [examInProgress, setExamInProgress] = useState(false);
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<number[]>([]);
  const [examCompleted, setExamCompleted] = useState(false);
  const [examScore, setExamScore] = useState(0);
  const [timeRemaining, setTimeRemaining] = useState(90 * 60); // 90 minutes in seconds
  const [expandedFaq, setExpandedFaq] = useState<string | null>(null);
  const [verifyCredentialId, setVerifyCredentialId] = useState('');
  const [verificationResult, setVerificationResult] = useState<{ valid: boolean; cert?: UserCertification & { certName: string } } | null>(null);

  const startPracticeExam = (cert: Certification) => {
    setSelectedCert(cert);
    setShowExamModal(true);
    setExamInProgress(false);
    setCurrentQuestion(0);
    setSelectedAnswers([]);
    setExamCompleted(false);
    setTimeRemaining(cert.examDuration * 60);
  };

  const beginExam = () => {
    setExamInProgress(true);
  };

  const handleAnswerSelect = (answerIndex: number) => {
    const question = sampleQuestions[currentQuestion];
    if (question.type === 'multiple_select') {
      if (selectedAnswers.includes(answerIndex)) {
        setSelectedAnswers(selectedAnswers.filter(a => a !== answerIndex));
      } else {
        setSelectedAnswers([...selectedAnswers, answerIndex]);
      }
    } else {
      setSelectedAnswers([answerIndex]);
    }
  };

  const nextQuestion = () => {
    if (currentQuestion < sampleQuestions.length - 1) {
      setCurrentQuestion(currentQuestion + 1);
      setSelectedAnswers([]);
    } else {
      // Calculate score
      let totalPoints = 0;
      let earnedPoints = 0;
      sampleQuestions.forEach((q, idx) => {
        totalPoints += q.points;
        // Simplified scoring for demo
        if (idx === currentQuestion) {
          const correct = q.correctAnswers.every(a => selectedAnswers.includes(a)) &&
            selectedAnswers.every(a => q.correctAnswers.includes(a));
          if (correct) earnedPoints += q.points;
        }
      });
      setExamScore(Math.round((earnedPoints / totalPoints) * 100));
      setExamCompleted(true);
    }
  };

  const verifyCredential = () => {
    // Simulate verification
    const found = userCertifications.find(uc => uc.credentialId === verifyCredentialId);
    if (found) {
      const cert = certifications.find(c => c.id === found.certificationId);
      setVerificationResult({
        valid: true,
        cert: { ...found, certName: cert?.name || '' },
      });
    } else {
      setVerificationResult({ valid: false });
    }
  };

  const formatTime = (seconds: number) => {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    if (hrs > 0) {
      return `${hrs}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const faqs = [
    {
      id: '1',
      question: 'How long is my certification valid?',
      answer: 'All HeroForge certifications are valid for 2 years from the date of passing. You can renew by retaking the exam or completing continuing education credits.',
    },
    {
      id: '2',
      question: 'What happens if I fail the exam?',
      answer: 'You can retake the exam after a 14-day waiting period. You get 3 attempts included with your exam purchase. Additional attempts can be purchased at 50% of the original price.',
    },
    {
      id: '3',
      question: 'Are the exams proctored?',
      answer: 'Yes, all certification exams are online proctored using our secure exam platform. You\'ll need a webcam, microphone, and stable internet connection.',
    },
    {
      id: '4',
      question: 'Can I use HeroForge during the practical portions?',
      answer: 'Yes! The practical portions are designed to test your ability to use HeroForge effectively. You\'ll have access to a sandboxed HeroForge environment during the exam.',
    },
    {
      id: '5',
      question: 'How do I share my certification?',
      answer: 'Once certified, you\'ll receive a digital badge through Credly that can be shared on LinkedIn, email signatures, and resumes. You\'ll also get a unique verification URL.',
    },
  ];

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-2">
              <Shield className="w-8 h-8 text-cyan-500" />
              <span className="text-xl font-bold text-white">HeroForge</span>
            </Link>
            <nav className="hidden md:flex items-center gap-6">
              <Link to="/features" className="text-gray-300 hover:text-white">Features</Link>
              <Link to="/pricing" className="text-gray-300 hover:text-white">Pricing</Link>
              <Link to="/academy" className="text-gray-300 hover:text-white">Academy</Link>
              <Link to="/docs" className="text-gray-300 hover:text-white">Docs</Link>
              <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Sign In</Link>
            </nav>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-16 bg-gradient-to-b from-gray-800 to-gray-900">
        <div className="max-w-7xl mx-auto px-4 text-center">
          <div className="inline-flex items-center gap-2 px-4 py-2 bg-amber-500/20 rounded-full mb-6">
            <Award className="w-5 h-5 text-amber-400" />
            <span className="text-amber-400 font-medium">Industry-Recognized Certifications</span>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-white mb-6">
            Validate Your Security Expertise
          </h1>
          <p className="text-xl text-gray-400 max-w-3xl mx-auto mb-8">
            Earn HeroForge certifications to demonstrate your mastery of security assessment,
            vulnerability management, and professional reporting skills.
          </p>
          <div className="flex flex-wrap justify-center gap-8 text-sm text-gray-400">
            <div className="flex items-center gap-2">
              <Users className="w-5 h-5 text-cyan-500" />
              <span>5,000+ Certified Professionals</span>
            </div>
            <div className="flex items-center gap-2">
              <BadgeCheck className="w-5 h-5 text-cyan-500" />
              <span>Credly Digital Badges</span>
            </div>
            <div className="flex items-center gap-2">
              <FileCheck className="w-5 h-5 text-cyan-500" />
              <span>Employer Verification Portal</span>
            </div>
          </div>
        </div>
      </section>

      {/* Certification Cards */}
      <section className="py-16">
        <div className="max-w-7xl mx-auto px-4">
          <h2 className="text-3xl font-bold text-white mb-8 text-center">Choose Your Certification Path</h2>
          <div className="grid md:grid-cols-3 gap-8">
            {certifications.map((cert) => {
              const userCert = userCertifications.find(uc => uc.certificationId === cert.id);
              return (
                <div
                  key={cert.id}
                  className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden hover:border-gray-600 transition-all"
                >
                  {/* Header */}
                  <div className={`bg-gradient-to-r ${cert.color} p-6`}>
                    <div className="flex items-center justify-between mb-4">
                      <div className="p-3 bg-white/20 rounded-lg">
                        {cert.icon}
                      </div>
                      {userCert && (
                        <span className="px-3 py-1 bg-green-500/20 text-green-400 rounded-full text-sm font-medium">
                          Earned
                        </span>
                      )}
                    </div>
                    <h3 className="text-2xl font-bold text-white">{cert.shortName}</h3>
                    <p className="text-white/80">{cert.name}</p>
                  </div>

                  {/* Body */}
                  <div className="p-6">
                    <p className="text-gray-400 mb-6">{cert.description}</p>

                    <div className="space-y-4 mb-6">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-gray-500">Exam Duration</span>
                        <span className="text-white">{cert.examDuration} minutes</span>
                      </div>
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-gray-500">Passing Score</span>
                        <span className="text-white">{cert.passingScore}%</span>
                      </div>
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-gray-500">Validity</span>
                        <span className="text-white">{cert.validity}</span>
                      </div>
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-gray-500">Prep Time</span>
                        <span className="text-white">{cert.duration}</span>
                      </div>
                    </div>

                    <div className="mb-6">
                      <h4 className="text-white font-medium mb-2">Exam Format</h4>
                      <div className="flex gap-2">
                        <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-xs">
                          {cert.examFormat.multipleChoice} MC
                        </span>
                        <span className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs">
                          {cert.examFormat.practical} Practical
                        </span>
                        <span className="px-2 py-1 bg-amber-500/20 text-amber-400 rounded text-xs">
                          {cert.examFormat.scenario} Scenario
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between mb-6">
                      <div>
                        <span className="text-3xl font-bold text-white">${cert.price}</span>
                        <span className="text-gray-500 ml-1">USD</span>
                      </div>
                    </div>

                    <div className="space-y-2">
                      {userCert ? (
                        <>
                          <button className="w-full py-3 bg-gray-700 text-white rounded-lg font-medium flex items-center justify-center gap-2">
                            <Download className="w-5 h-5" />
                            Download Certificate
                          </button>
                          <button className="w-full py-3 border border-gray-600 text-gray-300 rounded-lg font-medium flex items-center justify-center gap-2 hover:bg-gray-700">
                            <Share2 className="w-5 h-5" />
                            Share Badge
                          </button>
                        </>
                      ) : (
                        <>
                          <button className={`w-full py-3 bg-gradient-to-r ${cert.color} text-white rounded-lg font-medium hover:opacity-90`}>
                            Purchase Exam
                          </button>
                          <button
                            onClick={() => startPracticeExam(cert)}
                            className="w-full py-3 border border-gray-600 text-gray-300 rounded-lg font-medium flex items-center justify-center gap-2 hover:bg-gray-700"
                          >
                            <Play className="w-5 h-5" />
                            Try Practice Exam
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Certification Details */}
      <section className="py-16 bg-gray-800">
        <div className="max-w-7xl mx-auto px-4">
          <h2 className="text-3xl font-bold text-white mb-8 text-center">What You'll Learn</h2>
          <div className="grid md:grid-cols-3 gap-8">
            {certifications.map((cert) => (
              <div key={cert.id} className="bg-gray-900 rounded-xl p-6 border border-gray-700">
                <h3 className={`text-xl font-bold bg-gradient-to-r ${cert.color} bg-clip-text text-transparent mb-4`}>
                  {cert.shortName} Topics
                </h3>
                <ul className="space-y-2">
                  {cert.topics.map((topic, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-gray-400">
                      <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                      <span>{topic}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Benefits */}
      <section className="py-16">
        <div className="max-w-7xl mx-auto px-4">
          <h2 className="text-3xl font-bold text-white mb-8 text-center">Certification Benefits</h2>
          <div className="grid md:grid-cols-4 gap-6">
            <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 text-center">
              <div className="w-12 h-12 bg-cyan-500/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                <BadgeCheck className="w-6 h-6 text-cyan-500" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">Digital Badges</h3>
              <p className="text-gray-400 text-sm">Share on LinkedIn, email signatures, and resumes with Credly integration</p>
            </div>
            <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 text-center">
              <div className="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                <Users className="w-6 h-6 text-purple-500" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">Professional Directory</h3>
              <p className="text-gray-400 text-sm">Get listed in our certified professionals directory for employers</p>
            </div>
            <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 text-center">
              <div className="w-12 h-12 bg-amber-500/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                <Star className="w-6 h-6 text-amber-500" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">Exclusive Access</h3>
              <p className="text-gray-400 text-sm">Beta features, exclusive webinars, and priority support</p>
            </div>
            <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 text-center">
              <div className="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                <FileCheck className="w-6 h-6 text-green-500" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">Verification Portal</h3>
              <p className="text-gray-400 text-sm">Employers can verify your credentials instantly online</p>
            </div>
          </div>
        </div>
      </section>

      {/* Verification Section */}
      <section className="py-16 bg-gray-800">
        <div className="max-w-3xl mx-auto px-4">
          <h2 className="text-3xl font-bold text-white mb-8 text-center">Verify a Credential</h2>
          <div className="bg-gray-900 rounded-xl p-8 border border-gray-700">
            <p className="text-gray-400 mb-6 text-center">
              Enter a credential ID to verify if someone holds a valid HeroForge certification.
            </p>
            <div className="flex gap-4">
              <input
                type="text"
                value={verifyCredentialId}
                onChange={(e) => setVerifyCredentialId(e.target.value)}
                placeholder="Enter Credential ID (e.g., HCA-2025-78432)"
                className="flex-1 px-4 py-3 bg-gray-800 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={verifyCredential}
                className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium"
              >
                Verify
              </button>
            </div>

            {verificationResult && (
              <div className={`mt-6 p-4 rounded-lg ${verificationResult.valid ? 'bg-green-500/20 border border-green-500/50' : 'bg-red-500/20 border border-red-500/50'}`}>
                {verificationResult.valid && verificationResult.cert ? (
                  <div className="flex items-start gap-4">
                    <CheckCircle className="w-6 h-6 text-green-500 flex-shrink-0" />
                    <div>
                      <h4 className="text-green-400 font-semibold mb-2">Valid Certification</h4>
                      <div className="space-y-1 text-sm text-gray-300">
                        <p><strong>Certification:</strong> {verificationResult.cert.certName}</p>
                        <p><strong>Credential ID:</strong> {verificationResult.cert.credentialId}</p>
                        <p><strong>Earned:</strong> {new Date(verificationResult.cert.earnedDate).toLocaleDateString()}</p>
                        <p><strong>Expires:</strong> {new Date(verificationResult.cert.expiryDate).toLocaleDateString()}</p>
                        <p><strong>Status:</strong> <span className="text-green-400">Active</span></p>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-4">
                    <AlertCircle className="w-6 h-6 text-red-500" />
                    <div>
                      <h4 className="text-red-400 font-semibold">Credential Not Found</h4>
                      <p className="text-sm text-gray-400">This credential ID does not match any active certification.</p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section className="py-16">
        <div className="max-w-3xl mx-auto px-4">
          <h2 className="text-3xl font-bold text-white mb-8 text-center">Frequently Asked Questions</h2>
          <div className="space-y-4">
            {faqs.map((faq) => (
              <div key={faq.id} className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
                <button
                  onClick={() => setExpandedFaq(expandedFaq === faq.id ? null : faq.id)}
                  className="w-full px-6 py-4 flex items-center justify-between text-left"
                >
                  <span className="text-white font-medium">{faq.question}</span>
                  {expandedFaq === faq.id ? (
                    <ChevronUp className="w-5 h-5 text-gray-400" />
                  ) : (
                    <ChevronDown className="w-5 h-5 text-gray-400" />
                  )}
                </button>
                {expandedFaq === faq.id && (
                  <div className="px-6 pb-4">
                    <p className="text-gray-400">{faq.answer}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-16 bg-gradient-to-r from-cyan-600 to-blue-600">
        <div className="max-w-4xl mx-auto px-4 text-center">
          <h2 className="text-3xl font-bold text-white mb-4">Ready to Get Certified?</h2>
          <p className="text-xl text-white/80 mb-8">
            Start with our free practice exams and beginner academy path to prepare.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <Link
              to="/academy"
              className="px-8 py-3 bg-white text-cyan-600 rounded-lg font-semibold hover:bg-gray-100"
            >
              Start Learning
            </Link>
            <button
              onClick={() => startPracticeExam(certifications[0])}
              className="px-8 py-3 bg-cyan-700 text-white rounded-lg font-semibold hover:bg-cyan-800"
            >
              Try Practice Exam
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 py-8">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-400">
          <p>&copy; 2026 HeroForge. All rights reserved.</p>
        </div>
      </footer>

      {/* Exam Modal */}
      {showExamModal && selectedCert && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            {!examInProgress ? (
              /* Exam Instructions */
              <div className="p-8">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-2xl font-bold text-white">Practice Exam: {selectedCert.shortName}</h2>
                  <button onClick={() => setShowExamModal(false)} className="text-gray-400 hover:text-white">
                    <X className="w-6 h-6" />
                  </button>
                </div>

                <div className="bg-gray-700/50 rounded-lg p-6 mb-6">
                  <h3 className="text-lg font-semibold text-white mb-4">Exam Instructions</h3>
                  <ul className="space-y-2 text-gray-300">
                    <li className="flex items-start gap-2">
                      <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                      <span>This is a practice exam with {sampleQuestions.length} sample questions</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Clock className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                      <span>Time limit: {selectedCert.examDuration} minutes for the full exam</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Target className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
                      <span>Passing score: {selectedCert.passingScore}%</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <BookOpen className="w-5 h-5 text-purple-500 flex-shrink-0 mt-0.5" />
                      <span>Question types: Multiple choice, multiple select, and scenarios</span>
                    </li>
                  </ul>
                </div>

                <div className="flex justify-end gap-4">
                  <button
                    onClick={() => setShowExamModal(false)}
                    className="px-6 py-3 border border-gray-600 text-gray-300 rounded-lg hover:bg-gray-700"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={beginExam}
                    className={`px-6 py-3 bg-gradient-to-r ${selectedCert.color} text-white rounded-lg font-medium`}
                  >
                    Begin Practice Exam
                  </button>
                </div>
              </div>
            ) : examCompleted ? (
              /* Exam Results */
              <div className="p-8 text-center">
                <div className={`w-24 h-24 mx-auto mb-6 rounded-full flex items-center justify-center ${examScore >= selectedCert.passingScore ? 'bg-green-500/20' : 'bg-red-500/20'}`}>
                  {examScore >= selectedCert.passingScore ? (
                    <Trophy className="w-12 h-12 text-green-500" />
                  ) : (
                    <AlertCircle className="w-12 h-12 text-red-500" />
                  )}
                </div>
                <h2 className="text-2xl font-bold text-white mb-2">
                  {examScore >= selectedCert.passingScore ? 'Congratulations!' : 'Keep Practicing!'}
                </h2>
                <p className="text-gray-400 mb-6">
                  {examScore >= selectedCert.passingScore
                    ? 'You passed the practice exam!'
                    : `You need ${selectedCert.passingScore}% to pass.`}
                </p>
                <div className="text-6xl font-bold text-white mb-8">{examScore}%</div>
                <div className="flex justify-center gap-4">
                  <button
                    onClick={() => setShowExamModal(false)}
                    className="px-6 py-3 border border-gray-600 text-gray-300 rounded-lg hover:bg-gray-700"
                  >
                    Close
                  </button>
                  <button
                    onClick={() => {
                      setExamInProgress(false);
                      setCurrentQuestion(0);
                      setSelectedAnswers([]);
                      setExamCompleted(false);
                    }}
                    className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium"
                  >
                    Try Again
                  </button>
                </div>
              </div>
            ) : (
              /* Exam Questions */
              <div className="p-8">
                {/* Header */}
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <span className="text-gray-400">Question {currentQuestion + 1} of {sampleQuestions.length}</span>
                    <div className="w-48 h-2 bg-gray-700 rounded-full mt-2">
                      <div
                        className={`h-full bg-gradient-to-r ${selectedCert.color} rounded-full`}
                        style={{ width: `${((currentQuestion + 1) / sampleQuestions.length) * 100}%` }}
                      />
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-gray-400">
                    <Timer className="w-5 h-5" />
                    <span className="font-mono">{formatTime(timeRemaining)}</span>
                  </div>
                </div>

                {/* Question */}
                <div className="mb-6">
                  <span className="inline-block px-3 py-1 bg-gray-700 text-gray-300 rounded-full text-sm mb-4">
                    {sampleQuestions[currentQuestion].category}
                  </span>
                  <h3 className="text-xl text-white mb-2">{sampleQuestions[currentQuestion].question}</h3>
                  {sampleQuestions[currentQuestion].type === 'multiple_select' && (
                    <p className="text-sm text-cyan-400">Select all that apply</p>
                  )}
                </div>

                {/* Options */}
                <div className="space-y-3 mb-8">
                  {sampleQuestions[currentQuestion].options.map((option, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleAnswerSelect(idx)}
                      className={`w-full p-4 rounded-lg border text-left transition-all ${
                        selectedAnswers.includes(idx)
                          ? 'border-cyan-500 bg-cyan-500/20 text-white'
                          : 'border-gray-600 bg-gray-700/50 text-gray-300 hover:border-gray-500'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div className={`w-6 h-6 rounded-full border-2 flex items-center justify-center ${
                          selectedAnswers.includes(idx) ? 'border-cyan-500 bg-cyan-500' : 'border-gray-500'
                        }`}>
                          {selectedAnswers.includes(idx) && <CheckCircle className="w-4 h-4 text-white" />}
                        </div>
                        <span>{option}</span>
                      </div>
                    </button>
                  ))}
                </div>

                {/* Navigation */}
                <div className="flex justify-between">
                  <button
                    onClick={() => setShowExamModal(false)}
                    className="px-6 py-3 border border-gray-600 text-gray-300 rounded-lg hover:bg-gray-700"
                  >
                    Exit Exam
                  </button>
                  <button
                    onClick={nextQuestion}
                    disabled={selectedAnswers.length === 0}
                    className={`px-6 py-3 bg-gradient-to-r ${selectedCert.color} text-white rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2`}
                  >
                    {currentQuestion < sampleQuestions.length - 1 ? 'Next Question' : 'Submit Exam'}
                    <ArrowRight className="w-5 h-5" />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
