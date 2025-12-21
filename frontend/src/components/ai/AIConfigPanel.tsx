import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { Save, RotateCcw, Sliders } from 'lucide-react';
import { aiAPI } from '../../services/api';
import type { AIModelConfig, ScoringWeights } from '../../types';
import Button from '../ui/Button';

interface AIConfigPanelProps {
  onConfigUpdate?: () => void;
}

const AIConfigPanel: React.FC<AIConfigPanelProps> = ({ onConfigUpdate }) => {
  const [config, setConfig] = useState<AIModelConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [weights, setWeights] = useState<ScoringWeights>({
    cvss_weight: 0.25,
    exploit_weight: 0.20,
    asset_criticality_weight: 0.15,
    network_exposure_weight: 0.15,
    attack_path_weight: 0.10,
    compliance_weight: 0.08,
    business_context_weight: 0.07,
  });

  const defaultWeights: ScoringWeights = {
    cvss_weight: 0.25,
    exploit_weight: 0.20,
    asset_criticality_weight: 0.15,
    network_exposure_weight: 0.15,
    attack_path_weight: 0.10,
    compliance_weight: 0.08,
    business_context_weight: 0.07,
  };

  useEffect(() => {
    loadConfig();
  }, []);

  const loadConfig = async () => {
    try {
      setLoading(true);
      const response = await aiAPI.getConfig();
      setConfig(response.data);
      setWeights(response.data.weights);
    } catch (error) {
      console.error('Failed to load AI config:', error);
      toast.error('Failed to load AI configuration');
    } finally {
      setLoading(false);
    }
  };

  const handleWeightChange = (key: keyof ScoringWeights, value: number) => {
    setWeights((prev) => ({
      ...prev,
      [key]: value,
    }));
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      await aiAPI.updateConfig({ weights });
      toast.success('AI configuration updated');
      if (onConfigUpdate) {
        onConfigUpdate();
      }
    } catch (error) {
      console.error('Failed to save AI config:', error);
      toast.error('Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    setWeights(defaultWeights);
    toast.info('Weights reset to defaults');
  };

  const getTotalWeight = () => {
    return Object.values(weights).reduce((sum, w) => sum + w, 0);
  };

  const weightLabels: Record<keyof ScoringWeights, string> = {
    cvss_weight: 'CVSS Score',
    exploit_weight: 'Exploit Availability',
    asset_criticality_weight: 'Asset Criticality',
    network_exposure_weight: 'Network Exposure',
    attack_path_weight: 'Attack Path Risk',
    compliance_weight: 'Compliance Impact',
    business_context_weight: 'Business Context',
  };

  const weightDescriptions: Record<keyof ScoringWeights, string> = {
    cvss_weight: 'Base vulnerability severity from CVE database',
    exploit_weight: 'Whether exploits exist in the wild',
    asset_criticality_weight: 'Importance of the affected asset',
    network_exposure_weight: 'Internet-facing vs internal exposure',
    attack_path_weight: 'Position in potential attack chains',
    compliance_weight: 'Impact on regulatory compliance',
    business_context_weight: 'Overall business risk context',
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-2">
          <Sliders className="w-5 h-5 text-cyan-400" />
          <h3 className="text-lg font-medium text-white">AI Scoring Configuration</h3>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={handleReset}
          >
            <RotateCcw className="w-4 h-4 mr-1" />
            Reset
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={handleSave}
            loading={saving}
          >
            <Save className="w-4 h-4 mr-1" />
            Save
          </Button>
        </div>
      </div>

      {/* Total Weight Indicator */}
      <div className="mb-6 p-3 bg-gray-900/50 rounded-lg">
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">Total Weight</span>
          <span className={`text-lg font-bold ${
            Math.abs(getTotalWeight() - 1) < 0.01 ? 'text-green-400' : 'text-yellow-400'
          }`}>
            {(getTotalWeight() * 100).toFixed(0)}%
          </span>
        </div>
        {Math.abs(getTotalWeight() - 1) >= 0.01 && (
          <p className="text-xs text-yellow-400 mt-1">
            Weights should sum to 100% for optimal scoring
          </p>
        )}
      </div>

      {/* Weight Sliders */}
      <div className="space-y-4">
        {(Object.keys(weights) as Array<keyof ScoringWeights>).map((key) => (
          <div key={key} className="space-y-2">
            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium text-white">
                  {weightLabels[key]}
                </label>
                <p className="text-xs text-gray-400">{weightDescriptions[key]}</p>
              </div>
              <span className="text-sm font-mono text-cyan-400">
                {(weights[key] * 100).toFixed(0)}%
              </span>
            </div>
            <input
              type="range"
              min="0"
              max="50"
              step="1"
              value={weights[key] * 100}
              onChange={(e) => handleWeightChange(key, parseInt(e.target.value) / 100)}
              className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer
                         [&::-webkit-slider-thumb]:appearance-none
                         [&::-webkit-slider-thumb]:w-4
                         [&::-webkit-slider-thumb]:h-4
                         [&::-webkit-slider-thumb]:rounded-full
                         [&::-webkit-slider-thumb]:bg-cyan-500
                         [&::-webkit-slider-thumb]:cursor-pointer
                         [&::-webkit-slider-thumb]:transition-transform
                         [&::-webkit-slider-thumb]:hover:scale-110"
            />
          </div>
        ))}
      </div>

      {/* Config Info */}
      {config && (
        <div className="mt-6 pt-4 border-t border-gray-700">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-400">Configuration Name:</span>
              <span className="ml-2 text-white">{config.name}</span>
            </div>
            <div>
              <span className="text-gray-400">Last Updated:</span>
              <span className="ml-2 text-white">
                {new Date(config.updated_at).toLocaleString()}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AIConfigPanel;
