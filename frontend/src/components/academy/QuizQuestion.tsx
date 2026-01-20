import React from 'react';
import { CheckCircle, Circle, Square, CheckSquare, HelpCircle } from 'lucide-react';

interface QuizQuestionProps {
  questionNumber: number;
  totalQuestions: number;
  questionType: 'multiple_choice' | 'multiple_select' | 'true_false' | 'code_challenge';
  questionText: string;
  options: string[];
  points: number;
  selectedAnswer: number | boolean | number[] | null;
  onAnswer: (answer: number | boolean | number[]) => void;
  showFeedback?: boolean;
  isCorrect?: boolean;
  correctAnswer?: number | boolean | number[];
  explanation?: string | null;
  disabled?: boolean;
}

const QuizQuestion: React.FC<QuizQuestionProps> = ({
  questionNumber,
  totalQuestions,
  questionType,
  questionText,
  options,
  points,
  selectedAnswer,
  onAnswer,
  showFeedback = false,
  isCorrect,
  correctAnswer,
  explanation,
  disabled = false,
}) => {
  // Render based on question type
  const renderQuestion = () => {
    switch (questionType) {
      case 'multiple_choice':
        return renderMultipleChoice();
      case 'multiple_select':
        return renderMultipleSelect();
      case 'true_false':
        return renderTrueFalse();
      case 'code_challenge':
        return renderCodeChallenge();
      default:
        return renderMultipleChoice();
    }
  };

  // Multiple choice (single selection)
  const renderMultipleChoice = () => {
    const selected = typeof selectedAnswer === 'number' ? selectedAnswer : -1;
    const correct = typeof correctAnswer === 'number' ? correctAnswer : -1;

    return (
      <div className="space-y-3">
        {options.map((option, index) => {
          const isSelected = selected === index;
          const isCorrectOption = showFeedback && correct === index;
          const isWrongSelection = showFeedback && isSelected && !isCorrect;

          return (
            <button
              key={index}
              onClick={() => !disabled && onAnswer(index)}
              disabled={disabled}
              className={`w-full text-left p-4 rounded-lg border-2 transition-all flex items-center ${
                isCorrectOption
                  ? 'border-green-500 bg-green-900/20'
                  : isWrongSelection
                  ? 'border-red-500 bg-red-900/20'
                  : isSelected
                  ? 'border-cyan-500 bg-cyan-900/20'
                  : 'border-gray-700 hover:border-gray-600 bg-gray-800'
              } ${disabled ? 'cursor-not-allowed opacity-75' : ''}`}
            >
              <div
                className={`w-6 h-6 rounded-full border-2 flex items-center justify-center mr-3 ${
                  isCorrectOption
                    ? 'border-green-500 bg-green-500'
                    : isWrongSelection
                    ? 'border-red-500 bg-red-500'
                    : isSelected
                    ? 'border-cyan-500 bg-cyan-500'
                    : 'border-gray-500'
                }`}
              >
                {(isSelected || isCorrectOption) && (
                  <CheckCircle className="w-4 h-4 text-white" />
                )}
              </div>
              <span
                className={`${
                  isCorrectOption
                    ? 'text-green-400'
                    : isWrongSelection
                    ? 'text-red-400'
                    : isSelected
                    ? 'text-cyan-400'
                    : 'text-gray-300'
                }`}
              >
                {option}
              </span>
            </button>
          );
        })}
      </div>
    );
  };

  // Multiple select (multiple selections)
  const renderMultipleSelect = () => {
    const selected = Array.isArray(selectedAnswer) ? selectedAnswer : [];
    const correct = Array.isArray(correctAnswer) ? correctAnswer : [];

    const handleToggle = (index: number) => {
      if (disabled) return;
      const newSelected = selected.includes(index)
        ? selected.filter((i) => i !== index)
        : [...selected, index];
      onAnswer(newSelected);
    };

    return (
      <div className="space-y-3">
        <p className="text-sm text-gray-400 mb-2">Select all that apply</p>
        {options.map((option, index) => {
          const isSelected = selected.includes(index);
          const isCorrectOption = showFeedback && correct.includes(index);
          const isWrongSelection = showFeedback && isSelected && !correct.includes(index);
          const isMissed = showFeedback && !isSelected && correct.includes(index);

          return (
            <button
              key={index}
              onClick={() => handleToggle(index)}
              disabled={disabled}
              className={`w-full text-left p-4 rounded-lg border-2 transition-all flex items-center ${
                isCorrectOption && isSelected
                  ? 'border-green-500 bg-green-900/20'
                  : isWrongSelection
                  ? 'border-red-500 bg-red-900/20'
                  : isMissed
                  ? 'border-yellow-500 bg-yellow-900/20'
                  : isSelected
                  ? 'border-cyan-500 bg-cyan-900/20'
                  : 'border-gray-700 hover:border-gray-600 bg-gray-800'
              } ${disabled ? 'cursor-not-allowed opacity-75' : ''}`}
            >
              <div
                className={`w-6 h-6 rounded border-2 flex items-center justify-center mr-3 ${
                  isCorrectOption && isSelected
                    ? 'border-green-500 bg-green-500'
                    : isWrongSelection
                    ? 'border-red-500 bg-red-500'
                    : isMissed
                    ? 'border-yellow-500'
                    : isSelected
                    ? 'border-cyan-500 bg-cyan-500'
                    : 'border-gray-500'
                }`}
              >
                {isSelected && <CheckSquare className="w-4 h-4 text-white" />}
              </div>
              <span
                className={`${
                  isCorrectOption && isSelected
                    ? 'text-green-400'
                    : isWrongSelection
                    ? 'text-red-400'
                    : isMissed
                    ? 'text-yellow-400'
                    : isSelected
                    ? 'text-cyan-400'
                    : 'text-gray-300'
                }`}
              >
                {option}
              </span>
            </button>
          );
        })}
      </div>
    );
  };

  // True/False
  const renderTrueFalse = () => {
    const selected = typeof selectedAnswer === 'boolean' ? selectedAnswer : null;
    const correct = typeof correctAnswer === 'boolean' ? correctAnswer : null;

    const renderOption = (value: boolean, label: string) => {
      const isSelected = selected === value;
      const isCorrectOption = showFeedback && correct === value;
      const isWrongSelection = showFeedback && isSelected && !isCorrect;

      return (
        <button
          onClick={() => !disabled && onAnswer(value)}
          disabled={disabled}
          className={`flex-1 p-6 rounded-lg border-2 transition-all text-center ${
            isCorrectOption
              ? 'border-green-500 bg-green-900/20'
              : isWrongSelection
              ? 'border-red-500 bg-red-900/20'
              : isSelected
              ? 'border-cyan-500 bg-cyan-900/20'
              : 'border-gray-700 hover:border-gray-600 bg-gray-800'
          } ${disabled ? 'cursor-not-allowed opacity-75' : ''}`}
        >
          <span
            className={`text-xl font-bold ${
              isCorrectOption
                ? 'text-green-400'
                : isWrongSelection
                ? 'text-red-400'
                : isSelected
                ? 'text-cyan-400'
                : 'text-gray-300'
            }`}
          >
            {label}
          </span>
        </button>
      );
    };

    return (
      <div className="flex gap-4">
        {renderOption(true, 'True')}
        {renderOption(false, 'False')}
      </div>
    );
  };

  // Code challenge (multiple choice with code)
  const renderCodeChallenge = () => {
    // Similar to multiple choice but with monospace font for options
    const selected = typeof selectedAnswer === 'number' ? selectedAnswer : -1;
    const correct = typeof correctAnswer === 'number' ? correctAnswer : -1;

    return (
      <div className="space-y-3">
        {options.map((option, index) => {
          const isSelected = selected === index;
          const isCorrectOption = showFeedback && correct === index;
          const isWrongSelection = showFeedback && isSelected && !isCorrect;

          return (
            <button
              key={index}
              onClick={() => !disabled && onAnswer(index)}
              disabled={disabled}
              className={`w-full text-left p-4 rounded-lg border-2 transition-all flex items-start ${
                isCorrectOption
                  ? 'border-green-500 bg-green-900/20'
                  : isWrongSelection
                  ? 'border-red-500 bg-red-900/20'
                  : isSelected
                  ? 'border-cyan-500 bg-cyan-900/20'
                  : 'border-gray-700 hover:border-gray-600 bg-gray-800'
              } ${disabled ? 'cursor-not-allowed opacity-75' : ''}`}
            >
              <div
                className={`w-6 h-6 rounded-full border-2 flex items-center justify-center mr-3 mt-0.5 ${
                  isCorrectOption
                    ? 'border-green-500 bg-green-500'
                    : isWrongSelection
                    ? 'border-red-500 bg-red-500'
                    : isSelected
                    ? 'border-cyan-500 bg-cyan-500'
                    : 'border-gray-500'
                }`}
              >
                {(isSelected || isCorrectOption) && (
                  <CheckCircle className="w-4 h-4 text-white" />
                )}
              </div>
              <pre
                className={`font-mono text-sm whitespace-pre-wrap ${
                  isCorrectOption
                    ? 'text-green-400'
                    : isWrongSelection
                    ? 'text-red-400'
                    : isSelected
                    ? 'text-cyan-400'
                    : 'text-gray-300'
                }`}
              >
                {option}
              </pre>
            </button>
          );
        })}
      </div>
    );
  };

  return (
    <div className="bg-gray-800 rounded-xl p-6 mb-6">
      {/* Question header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center">
          <span className="text-sm font-medium text-gray-500">
            Question {questionNumber} of {totalQuestions}
          </span>
          <span className="mx-2 text-gray-600">•</span>
          <span className="text-sm text-cyan-400">{points} point{points !== 1 ? 's' : ''}</span>
        </div>
        <span
          className={`text-xs px-2 py-1 rounded ${
            questionType === 'multiple_choice'
              ? 'bg-blue-900/50 text-blue-400'
              : questionType === 'multiple_select'
              ? 'bg-purple-900/50 text-purple-400'
              : questionType === 'true_false'
              ? 'bg-green-900/50 text-green-400'
              : 'bg-orange-900/50 text-orange-400'
          }`}
        >
          {questionType.replace('_', ' ')}
        </span>
      </div>

      {/* Question text */}
      <h3 className="text-lg text-white mb-6">{questionText}</h3>

      {/* Options */}
      {renderQuestion()}

      {/* Feedback */}
      {showFeedback && (
        <div
          className={`mt-6 p-4 rounded-lg ${
            isCorrect ? 'bg-green-900/20 border border-green-700' : 'bg-red-900/20 border border-red-700'
          }`}
        >
          <div className="flex items-center mb-2">
            {isCorrect ? (
              <>
                <CheckCircle className="w-5 h-5 text-green-400 mr-2" />
                <span className="text-green-400 font-medium">Correct!</span>
              </>
            ) : (
              <>
                <HelpCircle className="w-5 h-5 text-red-400 mr-2" />
                <span className="text-red-400 font-medium">Incorrect</span>
              </>
            )}
          </div>
          {explanation && <p className="text-gray-400 text-sm">{explanation}</p>}
        </div>
      )}
    </div>
  );
};

export default QuizQuestion;
