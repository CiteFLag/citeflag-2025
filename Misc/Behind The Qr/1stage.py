import os
import numpy as np
import matplotlib.pyplot as plt
from scipy.io import wavfile
from scipy import signal

def analyze_spectrogram(audio_path, output_path=None, cmap='viridis'):
    """
    Performs spectrogram analysis on an audio file and displays/saves the result
    
    Parameters:
    -----------
    audio_path : str
        Path to the audio file
    output_path : str, optional
        Path to save the spectrogram image, if None, just display
    cmap : str, optional
        Colormap for the spectrogram visualization
    """
    print(f"Analyzing: {audio_path}")
    
    # Read the audio file
    try:
        sample_rate, audio_data = wavfile.read(audio_path)
        print(f"Sample rate: {sample_rate} Hz")
        print(f"Duration: {len(audio_data)/sample_rate:.2f} seconds")
    except Exception as e:
        print(f"Error reading audio file: {e}")
        return
    
    # Convert to mono if stereo
    if len(audio_data.shape) > 1:
        print("Converting stereo to mono")
        audio_data = audio_data.mean(axis=1)
    
    # Create the spectrogram
    plt.figure(figsize=(12, 8))
    
    # Generate and plot the spectrogram with higher resolution
    frequencies, times, spectrogram = signal.spectrogram(audio_data, sample_rate, 
                                                         nperseg=2048, noverlap=1024)
    
    # Plot both standard and high-contrast versions
    plt.subplot(2, 1, 1)
    plt.pcolormesh(times, frequencies, 10 * np.log10(spectrogram), shading='gouraud', cmap=cmap)
    plt.title('Standard Spectrogram')
    plt.ylabel('Frequency [Hz]')
    plt.colorbar(label='Intensity [dB]')
    
    plt.subplot(2, 1, 2)
    plt.pcolormesh(times, frequencies, 10 * np.log10(spectrogram), shading='gouraud', 
                  cmap=cmap, vmin=-80, vmax=0)  # High contrast for hidden patterns
    plt.title('High Contrast Spectrogram (Better for hidden text)')
    plt.xlabel('Time [sec]')
    plt.ylabel('Frequency [Hz]')
    plt.colorbar(label='Intensity [dB]')
    
    plt.tight_layout()
    
    # Save or display the spectrogram
    if output_path:
        plt.savefig(output_path, dpi=300)
        print(f"Spectrogram saved to: {output_path}")
    else:
        plt.show()
    
    print("Analysis complete!")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Audio Spectrogram Analyzer")
    parser.add_argument("audio_file", help="Path to the audio file to analyze")
    parser.add_argument("--output", "-o", help="Path to save the spectrogram image")
    parser.add_argument("--colormap", "-c", default="viridis", 
                        help="Colormap for visualization (viridis, plasma, inferno, magma, etc.)")
    
    args = parser.parse_args()
    
    analyze_spectrogram(args.audio_file, args.output, args.colormap)