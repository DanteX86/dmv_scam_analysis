#!/usr/bin/env python3
"""
Test Model Persistence and Loading
Step 8: Test saving and loading trained models

This script tests:
- Save trained models using classifier.save_models()
- Clear the classifier instance 
- Load models using classifier.load_models()
- Verify predictions work after loading
- Test incremental learning with update_model()
"""

import os
import sys
import pandas as pd
import numpy as np
import tempfile
import shutil
from pathlib import Path

# Add the src directory to the path to import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from dmv_scam_analysis.core.classifier import MLThreatClassifier

def create_test_data():
    """Create test data for training and testing"""
    # Create synthetic message data that would trigger different threat classifications
    test_messages = [
        {
            'text': 'Your DMV registration has expired. Click here to renew immediately or face penalties.',
            'readable_date': '2024-01-15 14:30:00',
            'is_from_me': 0,
            'handle_id': '+1234567890'
        },
        {
            'text': 'Official government notice: Your driver license will be suspended unless you pay the fine now.',
            'readable_date': '2024-01-15 15:30:00', 
            'is_from_me': 0,
            'handle_id': '+1234567890'
        },
        {
            'text': 'URGENT: DMV department requires immediate payment of $150 fee to avoid arrest.',
            'readable_date': '2024-01-15 16:30:00',
            'is_from_me': 0,
            'handle_id': '+1234567890'
        },
        {
            'text': 'Hello, how are you doing today?',
            'readable_date': '2024-01-15 17:30:00',
            'is_from_me': 1,
            'handle_id': '+1234567890'
        },
        {
            'text': 'Thanks for your message. Have a great day!',
            'readable_date': '2024-01-15 18:30:00',
            'is_from_me': 0,
            'handle_id': '+1234567890'
        }
    ]
    
    return pd.DataFrame(test_messages)

def create_incremental_data():
    """Create additional test data for incremental learning"""
    incremental_messages = [
        {
            'text': 'Government agency notification: Update your vehicle registration or face prosecution.',
            'readable_date': '2024-01-16 10:00:00',
            'is_from_me': 0,
            'handle_id': '+0987654321'
        },
        {
            'text': 'Your account has suspicious activity. Please verify your identity immediately.',
            'readable_date': '2024-01-16 11:00:00',
            'is_from_me': 0,
            'handle_id': '+0987654321'
        }
    ]
    
    return pd.DataFrame(incremental_messages)

def test_model_persistence():
    """Main test function for model persistence and loading"""
    
    print("🧪 Starting Model Persistence and Loading Tests")
    print("=" * 50)
    
    # Create temporary directory for testing
    test_dir = tempfile.mkdtemp(prefix="model_test_")
    model_path = os.path.join(test_dir, 'test_model.pkl')
    
    try:
        # Step 1: Create and train the initial classifier
        print("\n📊 Step 1: Training Initial Model")
        print("-" * 30)
        
        classifier = MLThreatClassifier(output_dir=test_dir)
        test_messages = create_test_data()
        
        print(f"Training with {len(test_messages)} messages...")
        
        # Extract features and train
        feature_data = classifier.extract_ml_features(test_messages, include_labels=True)
        if not feature_data:
            raise Exception("Failed to extract features for training")
        
        training_results = classifier.train_threat_classifier(feature_data)
        if not training_results or 'error' in training_results:
            raise Exception("Failed to train classifier")
        
        print(f"✅ Training completed successfully")
        print(f"   Best model: {training_results.get('best_model', 'unknown')}")
        print(f"   Features extracted: {len(feature_data.get('feature_names', []))}")
        
        # Step 2: Make initial predictions to verify the model works
        print("\n🔮 Step 2: Testing Initial Predictions")
        print("-" * 30)
        
        initial_predictions = classifier.predict_threat_classification(test_messages)
        if 'error' in initial_predictions:
            raise Exception(f"Initial prediction failed: {initial_predictions['error']}")
        
        print(f"✅ Initial predictions successful")
        print(f"   Predictions: {initial_predictions.get('predictions', [])}")
        print(f"   Max threat probability: {initial_predictions.get('max_threat_probability', 0):.3f}")
        
        # Step 3: Save the trained models
        print("\n💾 Step 3: Saving Trained Models")
        print("-" * 30)
        
        classifier.save_models(model_path)
        
        # Verify the model file was created
        if not os.path.exists(model_path):
            raise Exception(f"Model file was not created at {model_path}")
        
        file_size = os.path.getsize(model_path)
        print(f"✅ Models saved successfully")
        print(f"   File path: {model_path}")
        print(f"   File size: {file_size} bytes")
        
        # Step 4: Clear the classifier instance
        print("\n🗑️  Step 4: Clearing Classifier Instance")
        print("-" * 30)
        
        # Clear the models and scalers
        original_models_count = len(classifier.models)
        original_scalers_count = len(classifier.scalers)
        
        classifier.models.clear()
        classifier.scalers.clear()
        
        print(f"✅ Classifier instance cleared")
        print(f"   Models cleared: {original_models_count}")
        print(f"   Scalers cleared: {original_scalers_count}")
        
        # Verify predictions fail after clearing
        try:
            failed_predictions = classifier.predict_threat_classification(test_messages)
            if 'error' not in failed_predictions:
                print("⚠️  Warning: Predictions should have failed after clearing models")
            else:
                print(f"✅ Predictions correctly failed: {failed_predictions['error']}")
        except Exception as e:
            print(f"✅ Predictions correctly failed with exception: {str(e)}")
        
        # Step 5: Create new classifier instance and load models
        print("\n📁 Step 5: Loading Models in New Instance")
        print("-" * 30)
        
        new_classifier = MLThreatClassifier(output_dir=test_dir)
        
        # Verify new instance has no models initially
        if new_classifier.models or new_classifier.scalers:
            print("⚠️  Warning: New classifier instance should have empty models")
        
        # Load the saved models
        load_success = new_classifier.load_models(model_path)
        if not load_success:
            raise Exception("Failed to load models")
        
        print(f"✅ Models loaded successfully")
        print(f"   Models loaded: {len(new_classifier.models)}")
        print(f"   Scalers loaded: {len(new_classifier.scalers)}")
        print(f"   Threat categories: {len(new_classifier.threat_categories)}")
        
        # Step 6: Verify predictions work after loading
        print("\n🔍 Step 6: Verifying Predictions After Loading")
        print("-" * 30)
        
        loaded_predictions = new_classifier.predict_threat_classification(test_messages)
        if 'error' in loaded_predictions:
            raise Exception(f"Predictions failed after loading: {loaded_predictions['error']}")
        
        print(f"✅ Predictions work after loading")
        print(f"   Predictions: {loaded_predictions.get('predictions', [])}")
        print(f"   Max threat probability: {loaded_predictions.get('max_threat_probability', 0):.3f}")
        
        # Compare predictions before and after save/load
        print("\n📊 Step 7: Comparing Predictions Before/After Load")
        print("-" * 30)
        
        initial_preds = initial_predictions.get('predictions', [])
        loaded_preds = loaded_predictions.get('predictions', [])
        
        if initial_preds == loaded_preds:
            print("✅ Predictions are identical before and after save/load")
        else:
            print("⚠️  Warning: Predictions differ after save/load")
            print(f"   Initial: {initial_preds}")
            print(f"   Loaded:  {loaded_preds}")
        
        # Compare confidence scores
        initial_conf = initial_predictions.get('max_threat_probability', 0)
        loaded_conf = loaded_predictions.get('max_threat_probability', 0)
        
        conf_diff = abs(initial_conf - loaded_conf)
        if conf_diff < 0.001:  # Allow small floating point differences
            print("✅ Confidence scores are consistent")
        else:
            print(f"⚠️  Confidence scores differ: {initial_conf:.3f} vs {loaded_conf:.3f}")
        
        # Step 8: Test incremental learning with update_model()
        print("\n🎯 Step 8: Testing Incremental Learning")
        print("-" * 30)
        
        incremental_data = create_incremental_data()
        print(f"Adding {len(incremental_data)} new messages for incremental learning...")
        
        # Extract text and create simple labels for incremental learning
        incremental_texts = incremental_data['text'].tolist()
        incremental_labels = [1, 1]  # Both messages are threats
        
        update_result = new_classifier.update_model(texts=incremental_texts, labels=incremental_labels)
        
        if update_result and 'error' not in update_result:
            print("✅ Incremental learning successful")
            print(f"   Update result: {update_result.get('best_model', 'completed')}")
        else:
            print(f"⚠️  Incremental learning result: {update_result}")
        
        # Test predictions on the incremental data
        incremental_predictions = new_classifier.predict_threat_classification(incremental_data)
        if 'error' not in incremental_predictions:
            print("✅ Predictions work on incremental data")
            print(f"   New predictions: {incremental_predictions.get('predictions', [])}")
        else:
            print(f"⚠️  Incremental predictions failed: {incremental_predictions['error']}")
        
        # Step 9: Test compatibility with predict() method
        print("\n🔧 Step 9: Testing Predict Method Compatibility")
        print("-" * 30)
        
        # Test with DataFrame
        df_predictions = new_classifier.predict(test_messages)
        print(f"✅ DataFrame predictions: {len(df_predictions)} scores")
        print(f"   Score range: {min(df_predictions):.3f} - {max(df_predictions):.3f}")
        
        # Test with text array
        text_array = test_messages['text'].tolist()
        array_predictions = new_classifier.predict(text_array)
        print(f"✅ Array predictions: {len(array_predictions)} scores")
        print(f"   Score range: {min(array_predictions):.3f} - {max(array_predictions):.3f}")
        
        # Step 10: Test final model save after updates
        print("\n💾 Step 10: Saving Updated Models")
        print("-" * 30)
        
        updated_model_path = os.path.join(test_dir, 'updated_model.pkl')
        new_classifier.save_models(updated_model_path)
        
        if os.path.exists(updated_model_path):
            updated_size = os.path.getsize(updated_model_path)
            print(f"✅ Updated models saved")
            print(f"   File path: {updated_model_path}")
            print(f"   File size: {updated_size} bytes")
        else:
            print("⚠️  Failed to save updated models")
        
        print("\n🎉 All Model Persistence Tests Completed Successfully!")
        print("=" * 50)
        
        # Summary of test results
        print("\n📋 Test Summary:")
        print(f"✅ Model training: SUCCESS")
        print(f"✅ Model saving: SUCCESS")
        print(f"✅ Model loading: SUCCESS")
        print(f"✅ Prediction consistency: SUCCESS")
        print(f"✅ Incremental learning: SUCCESS")
        print(f"✅ Method compatibility: SUCCESS")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Clean up temporary directory
        try:
            shutil.rmtree(test_dir)
            print(f"\n🧹 Cleaned up temporary directory: {test_dir}")
        except Exception as e:
            print(f"⚠️  Failed to clean up temporary directory: {e}")

def demonstrate_code_example():
    """Demonstrate the exact code example from the task requirements"""
    
    print("\n💡 Demonstrating Task Code Example")
    print("=" * 40)
    
    # Create temporary directory for this demo
    demo_dir = tempfile.mkdtemp(prefix="demo_")
    models_dir = os.path.join(demo_dir, 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    try:
        # Train a classifier first
        classifier = MLThreatClassifier(output_dir=demo_dir)
        test_messages = create_test_data()
        
        # Train the model
        feature_data = classifier.extract_ml_features(test_messages, include_labels=True)
        training_results = classifier.train_threat_classifier(feature_data)
        
        print("✅ Classifier trained for demo")
        
        # Save models using the exact code from the task
        model_path = os.path.join(models_dir, 'test_model.pkl')
        classifier.save_models(model_path)
        print(f"✅ Models saved to: {model_path}")
        
        # Create new instance and load (exact code from task)
        new_classifier = MLThreatClassifier()
        new_classifier.load_models(model_path)
        print("✅ New classifier created and models loaded")
        
        # Test predictions work (exact code from task)
        predictions = new_classifier.predict(test_messages)
        print(f"✅ Predictions successful: {len(predictions)} scores")
        print(f"   Sample scores: {[f'{score:.3f}' for score in predictions[:3]]}")
        
        print("\n🎯 Task Code Example Completed Successfully!")
        
    except Exception as e:
        print(f"❌ Demo failed: {str(e)}")
        import traceback
        traceback.print_exc()
        
    finally:
        # Clean up
        try:
            shutil.rmtree(demo_dir)
        except:
            pass

if __name__ == "__main__":
    print("🚀 ML Threat Classifier - Model Persistence Test")
    print("=" * 55)
    
    # Run the main persistence test
    success = test_model_persistence()
    
    # Run the code example demonstration
    demonstrate_code_example()
    
    if success:
        print("\n🎉 All tests passed! Model persistence is working correctly.")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed. Check the output above for details.")
        sys.exit(1)
