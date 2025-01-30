# main.py
import argparse
import logging
import sys
from typing import Dict, List

from com_security_analyzer.core.base import BaseAnalyzer, AnalysisResult
from com_security_analyzer.modules.registry import RegistryAnalyzer
from com_security_analyzer.modules.security import SecurityAnalyzer
from com_security_analyzer.modules.method_discovery import MethodDiscoveryAnalyzer
from com_security_analyzer.modules.vulnerability import VulnerabilityAnalyzer
from com_security_analyzer.core.report import ReportGenerator

logger = logging.getLogger(__name__)

class ComSecurityAnalyzer:
    """Main class coordinating the analysis modules"""
    
    AVAILABLE_MODULES = {
        'registry': RegistryAnalyzer,
        'security': SecurityAnalyzer,
        'methods': MethodDiscoveryAnalyzer,
        'vulnerabilities': VulnerabilityAnalyzer
    }
    
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.analyzers = self._initialize_analyzers()
        self.results: Dict[str, AnalysisResult] = {}

    def _initialize_analyzers(self) -> List[BaseAnalyzer]:
        """Initialize analyzers based on command line arguments"""
        analyzers = []
        available_modules = self.AVAILABLE_MODULES.copy()
        
        if self.args.skip:
            skip_modules = [m.strip().lower() for m in self.args.skip.split(',')]
            for module in skip_modules:
                if module in available_modules:
                    logger.info(f"Skipping module: {module}")
                    available_modules.pop(module)
                else:
                    logger.warning(f"Unknown module to skip: {module}")
        
        if self.args.modules:
            requested_modules = [m.strip().lower() for m in self.args.modules.split(',')]
            for module in requested_modules:
                if module in available_modules:
                    analyzers.append(available_modules[module]())
                else:
                    logger.error(f"Unknown module requested: {module}")
                    sys.exit(1)
        else:
            analyzers = [cls() for cls in available_modules.values()]
        
        # Ensure registry analyzer is always first if present
        if 'registry' in available_modules and analyzers:
            reg_analyzer = next((a for a in analyzers if isinstance(a, RegistryAnalyzer)), None)
            if reg_analyzer:
                analyzers.remove(reg_analyzer)
                analyzers.insert(0, reg_analyzer)
        
        return analyzers

    def run(self):
        """Execute all analysis modules and generate report"""
        try:
            if not self.analyzers:
                logger.error("No analyzers selected to run!")
                sys.exit(1)

            logger.info("Starting analysis with modules: %s", 
                       ', '.join(a.__class__.__name__ for a in self.analyzers))
            
            for analyzer in self.analyzers:
                analyzer_name = analyzer.__class__.__name__
                logger.info(f"Running {analyzer_name}...")
                
                # Debug logging
                logger.debug(f"Current results before {analyzer_name}: {self.results}")
                
                result = analyzer.analyze(self.results)
                
                # Debug logging
                logger.debug(f"Result type from {analyzer_name}: {type(result)}")
                logger.debug(f"Result content from {analyzer_name}: {result}")
                
                self.results[analyzer_name] = result

            # Generate report
            report = ReportGenerator(self.results)
            if self.args.output:
                report.save_to_file(self.args.output)
            else:
                print(report.generate_summary())

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            if self.args.debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)

def setup_logging(debug: bool = False):
    """Configure logging settings"""
    level = logging.DEBUG if debug else logging.INFO
    format_str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Add colors for different log levels
    if debug:
        format_str = '\033[1;37m%(asctime)s\033[0m - ' \
                    '\033[1;35m%(name)s\033[0m - ' \
                    '\033[1;%(color)sm%(levelname)s\033[0m - ' \
                    '%(message)s'
                    
        class ColoredFormatter(logging.Formatter):
            level_colors = {
                logging.DEBUG: '36',    # Cyan
                logging.INFO: '32',     # Green
                logging.WARNING: '33',  # Yellow
                logging.ERROR: '31',    # Red
                logging.CRITICAL: '41'  # Red background
            }

            def format(self, record):
                record.color = self.level_colors.get(record.levelno, '37')
                return logging.Formatter(format_str).format(record)

        handler = logging.StreamHandler()
        handler.setFormatter(ColoredFormatter())
        logging.root.handlers = [handler]
    
    logging.basicConfig(
        level=level,
        format=format_str
    )

def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="COM Security Analyzer - Analyze COM objects for security issues"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file for detailed report",
        type=str
    )
    parser.add_argument(
        "-d", "--debug",
        help="Enable debug logging",
        action="store_true"
    )
    parser.add_argument(
        "-m", "--modules",
        help="Specific modules to run (comma-separated): registry,security,methods,vulnerabilities",
        type=str
    )
    parser.add_argument(
        "-s", "--skip",
        help="Modules to skip (comma-separated): registry,security,methods,vulnerabilities",
        type=str
    )
    parser.add_argument(
        "--list-modules",
        help="List available modules and exit",
        action="store_true"
    )
    return parser.parse_args()

def main():
    """Main entry point"""
    args = parse_args()
    setup_logging(args.debug)
    
    if args.list_modules:
        print("\nAvailable modules:")
        for name, module in ComSecurityAnalyzer.AVAILABLE_MODULES.items():
            print(f"  {name}: {module.__doc__.split('\n')[0] if module.__doc__ else ''}")
        sys.exit(0)
    
    logger.info("Starting COM Security Analysis...")
    analyzer = ComSecurityAnalyzer(args)
    analyzer.run()
    logger.info("Analysis complete.")

__all__ = ['main', 'ComSecurityAnalyzer']

if __name__ == "__main__":
    main()