import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import App from '../App';
import { Header } from '../components/Header';

describe('Sentinel-EDR Frontend Scaffold', () => {
  it('renders the application shell successfully', () => {
    const { container } = render(<App />);
    expect(container).toBeInTheDocument();
  });

  it('displays the expected Sentinel-EDR application identity', () => {
    render(<App />);
    const heading = screen.getByRole('heading', { name: /Sentinel-EDR SOC Console Scaffold/i });
    expect(heading).toBeInTheDocument();
  });

  it('renders and queries the basic Header component with custom status', () => {
    render(<Header statusText="Testing Mode" />);
    expect(screen.getByText('Sentinel-EDR')).toBeInTheDocument();
    expect(screen.getByText('Endpoint Detection & Response Console')).toBeInTheDocument();
    expect(screen.getByText('Testing Mode')).toBeInTheDocument();
  });

  it('executes in a DOM-like test environment and queries elements', () => {
    render(<App />);
    const footerText = screen.getByText(/Hybrid Endpoint Detection and Response System/i);
    expect(footerText).toBeInTheDocument();
    expect(document.body).toBeInTheDocument();
  });

  it('operates independently without production API credentials or live backend', () => {
    // Verifies the application shell renders purely from local components without throwing
    expect(() => render(<App />)).not.toThrow();
  });
});
