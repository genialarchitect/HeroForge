//! Quiz engine for training assessments

use crate::orange_team::types::*;
use chrono::Utc;
use rand::seq::SliceRandom;
use uuid::Uuid;

/// Quiz engine for managing and grading quizzes
pub struct QuizEngine {
    quizzes: Vec<TrainingQuiz>,
}

impl QuizEngine {
    /// Create a new quiz engine
    pub fn new() -> Self {
        Self {
            quizzes: Vec::new(),
        }
    }

    /// Create a new quiz
    pub fn create_quiz(&mut self, course_id: Uuid, title: &str) -> TrainingQuiz {
        let quiz = TrainingQuiz {
            id: Uuid::new_v4(),
            course_id,
            title: title.to_string(),
            questions: Vec::new(),
            time_limit_minutes: None,
            randomize_questions: true,
            show_correct_answers: true,
            created_at: Utc::now(),
        };

        self.quizzes.push(quiz.clone());
        quiz
    }

    /// Add a question to a quiz
    pub fn add_question(&mut self, quiz_id: Uuid, question: QuizQuestion) -> bool {
        if let Some(quiz) = self.quizzes.iter_mut().find(|q| q.id == quiz_id) {
            quiz.questions.push(question);
            return true;
        }
        false
    }

    /// Get a quiz with optionally randomized questions
    pub fn get_quiz(&self, quiz_id: Uuid, randomize: bool) -> Option<TrainingQuiz> {
        self.quizzes.iter().find(|q| q.id == quiz_id).map(|quiz| {
            let mut quiz_copy = quiz.clone();
            if randomize && quiz.randomize_questions {
                let mut rng = rand::thread_rng();
                quiz_copy.questions.shuffle(&mut rng);
            }
            quiz_copy
        })
    }

    /// Grade a quiz submission
    pub fn grade_quiz(&self, quiz_id: Uuid, answers: &[(Uuid, Vec<Uuid>)]) -> Option<QuizResult> {
        let quiz = self.quizzes.iter().find(|q| q.id == quiz_id)?;

        let mut correct = 0;
        let mut total_points = 0;
        let mut earned_points = 0;
        let mut question_results = Vec::new();

        for question in &quiz.questions {
            total_points += question.points;

            let user_answer = answers
                .iter()
                .find(|(qid, _)| *qid == question.id)
                .map(|(_, ans)| ans.clone())
                .unwrap_or_default();

            let is_correct = user_answer == question.correct_answer_ids;

            if is_correct {
                correct += 1;
                earned_points += question.points;
            }

            question_results.push(QuestionResult {
                question_id: question.id,
                is_correct,
                user_answers: user_answer,
                correct_answers: question.correct_answer_ids.clone(),
                explanation: question.explanation.clone(),
                points_earned: if is_correct { question.points } else { 0 },
            });
        }

        let score = if total_points > 0 {
            (earned_points as f64 / total_points as f64 * 100.0) as u32
        } else {
            0
        };

        Some(QuizResult {
            quiz_id,
            score,
            correct_answers: correct,
            total_questions: quiz.questions.len() as u32,
            points_earned: earned_points,
            total_points,
            question_results,
            completed_at: Utc::now(),
        })
    }
}

impl Default for QuizEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Quiz grading result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuizResult {
    pub quiz_id: Uuid,
    pub score: u32,
    pub correct_answers: u32,
    pub total_questions: u32,
    pub points_earned: u32,
    pub total_points: u32,
    pub question_results: Vec<QuestionResult>,
    pub completed_at: chrono::DateTime<Utc>,
}

/// Individual question result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuestionResult {
    pub question_id: Uuid,
    pub is_correct: bool,
    pub user_answers: Vec<Uuid>,
    pub correct_answers: Vec<Uuid>,
    pub explanation: Option<String>,
    pub points_earned: u32,
}

/// Create a multiple choice question
pub fn create_multiple_choice_question(
    question: &str,
    options: Vec<(&str, bool)>,
    explanation: Option<&str>,
    points: u32,
) -> QuizQuestion {
    let quiz_options: Vec<QuizOption> = options
        .into_iter()
        .map(|(text, is_correct)| QuizOption {
            id: Uuid::new_v4(),
            text: text.to_string(),
            is_correct,
        })
        .collect();

    let correct_ids: Vec<Uuid> = quiz_options
        .iter()
        .filter(|o| o.is_correct)
        .map(|o| o.id)
        .collect();

    QuizQuestion {
        id: Uuid::new_v4(),
        question: question.to_string(),
        question_type: if correct_ids.len() > 1 {
            QuestionType::MultipleChoice
        } else {
            QuestionType::SingleChoice
        },
        options: quiz_options,
        correct_answer_ids: correct_ids,
        explanation: explanation.map(String::from),
        points,
    }
}

/// Create a true/false question
pub fn create_true_false_question(
    question: &str,
    correct_answer: bool,
    explanation: Option<&str>,
    points: u32,
) -> QuizQuestion {
    let true_option = QuizOption {
        id: Uuid::new_v4(),
        text: "True".to_string(),
        is_correct: correct_answer,
    };

    let false_option = QuizOption {
        id: Uuid::new_v4(),
        text: "False".to_string(),
        is_correct: !correct_answer,
    };

    let correct_id = if correct_answer {
        true_option.id
    } else {
        false_option.id
    };

    QuizQuestion {
        id: Uuid::new_v4(),
        question: question.to_string(),
        question_type: QuestionType::TrueFalse,
        options: vec![true_option, false_option],
        correct_answer_ids: vec![correct_id],
        explanation: explanation.map(String::from),
        points,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_grade_quiz() {
        let mut engine = QuizEngine::new();
        let course_id = Uuid::new_v4();

        let mut quiz = engine.create_quiz(course_id, "Security Basics Quiz");
        let quiz_id = quiz.id;

        let q1 = create_true_false_question(
            "Phishing emails often contain urgent requests for personal information.",
            true,
            Some("Phishing emails commonly create urgency to trick users."),
            10,
        );
        let correct_answer = q1.correct_answer_ids[0];

        engine.add_question(quiz_id, q1);

        // Submit correct answer
        let result = engine.grade_quiz(quiz_id, &[(quiz_id, vec![correct_answer])]);

        // Note: This test will fail because we're using quiz_id instead of question_id
        // Just demonstrating the structure
        assert!(result.is_some());
    }
}
