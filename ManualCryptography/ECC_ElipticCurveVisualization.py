import numpy as np
import matplotlib.pyplot as plt
from matplotlib.widgets import Slider, Button
import matplotlib
matplotlib.use('TkAgg')

# Define our elliptic curve: y² = x³ + ax + b
def elliptic_curve(x, a, b):
    return np.sqrt(x**3 + a*x + b)

def is_on_curve(x, y, a, b):
    """Check if a point is on the curve y² = x³ + ax + b"""
    lhs = y**2
    rhs = x**3 + a*x + b
    return abs(lhs - rhs) < 1e-10  # Allow for floating-point imprecision

def update_curve(a, b):
    """Update the elliptic curve with new parameters"""
    # Clear previous plot
    ax.clear()
    
    # Generate x values
    x = np.linspace(x_range[0], x_range[1], 1000)
    
    # Filter values where y would be real (discriminant ≥ 0)
    valid_indices = x**3 + a*x + b >= 0
    x_valid = x[valid_indices]
    
    if len(x_valid) > 0:
        # Calculate y values (both positive and negative)
        y_positive = np.sqrt(x_valid**3 + a*x_valid + b)
        y_negative = -y_positive
        
        # Plot the curve
        curve_line, = ax.plot(x_valid, y_positive, 'b-', linewidth=2)
        ax.plot(x_valid, y_negative, 'b-', linewidth=2)
    
    # Set grid and labels
    ax.grid(True)
    ax.axhline(y=0, color='k', linestyle='-', alpha=0.3)
    ax.axvline(x=0, color='k', linestyle='-', alpha=0.3)
    ax.set_xlabel('x')
    ax.set_ylabel('y')
    ax.set_title(f'Elliptic Curve: y² = x³ + {a}x + {b}')
    
    # Make the plot square-ish
    ax.set_aspect('equal', adjustable='box')
    ax.set_xlim(x_range)
    ax.set_ylim(y_range)
    
    # Return the updated curve
    fig.canvas.draw_idle()
    
    return curve_line if 'curve_line' in locals() else None

def update_plot(val=None):
    """Update the entire plot with new parameters"""
    global a, b, curve_line
    a = a_slider.val
    b = b_slider.val
    
    curve_line = update_curve(a, b)
    
    # Reset points if they exist
    global P, Q, R, result, point_P, point_Q, point_R, point_result
    point_P = None
    point_Q = None
    point_R = None
    point_result = None
    P = None
    Q = None
    R = None
    result = None
    
    # Update the plot
    fig.canvas.draw_idle()

def find_y_on_curve(x, a, b):
    """Find y values on the curve for a given x"""
    y_squared = x**3 + a*x + b
    if y_squared < 0:
        return []
    elif y_squared == 0:
        return [0]
    else:
        y = np.sqrt(y_squared)
        return [y, -y]

def on_click(event):
    """Handle click events to select points on the curve"""
    global P, Q, point_P, point_Q, point_R, point_result, R, result
    
    if event.inaxes != ax or curve_line is None:
        return
    
    # Get the clicked point coordinates
    x_click = event.xdata
    y_click = event.ydata
    
    # Find the closest point on the curve
    x_curve = np.linspace(x_range[0], x_range[1], 1000)
    valid_indices = x_curve**3 + a*x_curve + b >= 0
    x_valid = x_curve[valid_indices]
    
    if len(x_valid) == 0:
        return
    
    # Find closest x value on the curve
    x_closest = x_valid[np.argmin(np.abs(x_valid - x_click))]
    
    # Find corresponding y values
    y_values = find_y_on_curve(x_closest, a, b)
    
    if not y_values:
        return
        
    # Choose the y value closest to the click
    y_closest = y_values[np.argmin(np.abs(np.array(y_values) - y_click))]
    
    # Assign to P or Q depending on which is not set
    if P is None:
        P = (x_closest, y_closest)
        if point_P:
            point_P.remove()
        point_P = ax.plot(P[0], P[1], 'ro', markersize=8)[0]
        ax.text(P[0] + 0.1, P[1], 'P', fontsize=12)
        fig.canvas.draw_idle()
    elif Q is None:
        Q = (x_closest, y_closest)
        if point_Q:
            point_Q.remove()
        point_Q = ax.plot(Q[0], Q[1], 'ro', markersize=8)[0]
        ax.text(Q[0] + 0.1, Q[1], 'Q', fontsize=12)
        
        # Now we have both P and Q, so add them
        add_points()
    else:
        # Clear all points and start over
        if point_P:
            point_P.remove()
        if point_Q:
            point_Q.remove()
        if point_R:
            point_R.remove()
        if point_result:
            point_result.remove()
        
        # Clear any added lines or text
        ax.lines = ax.lines[:1]  # Keep only the curve
        ax.texts = []
        
        P = (x_closest, y_closest)
        point_P = ax.plot(P[0], P[1], 'ro', markersize=8)[0]
        ax.text(P[0] + 0.1, P[1], 'P', fontsize=12)
        Q = None
        R = None
        result = None
        point_Q = None
        point_R = None
        point_result = None
        
        fig.canvas.draw_idle()

def add_points():
    """Add the two points P and Q on the curve"""
    global R, result, point_R, point_result
    
    if P is None or Q is None:
        return
    
    x_P, y_P = P
    x_Q, y_Q = Q
    
    # Special cases
    if x_P == x_Q and y_P == -y_Q:
        # P + Q = O (point at infinity)
        ax.text((x_P + x_Q)/2, 0, 'P + Q = O (point at infinity)', fontsize=12)
        fig.canvas.draw_idle()
        return
    
    # Compute the slope of the line through P and Q
    if x_P == x_Q:  # P = Q, tangent line
        lambda_val = (3 * x_P**2 + a) / (2 * y_P)
    else:
        lambda_val = (y_Q - y_P) / (x_Q - x_P)
    
    # Line equation: y = lambda * (x - x_P) + y_P
    x_line = np.linspace(x_range[0], x_range[1], 1000)
    y_line = lambda_val * (x_line - x_P) + y_P
    
    # Plot the line through P and Q
    ax.plot(x_line, y_line, 'g-', linewidth=1.5)
    
    # Find the third intersection point R
    # We solve: x³ + ax + b - (lambda*(x-x_P) + y_P)² = 0
    # The third root x_R can be found using the fact that the sum of roots equals -coeff of x²/coeff of x³
    x_R = lambda_val**2 - x_P - x_Q
    y_R = lambda_val * (x_P - x_R) - y_P  # Using the line equation
    
    # Plot R
    R = (x_R, y_R)
    point_R = ax.plot(x_R, y_R, 'mo', markersize=8)[0]
    ax.text(x_R + 0.1, y_R, 'R', fontsize=12)
    
    # The result of P + Q is R reflected across the x-axis
    y_result = -y_R
    result = (x_R, y_result)
    point_result = ax.plot(x_R, y_result, 'go', markersize=8)[0]
    ax.text(x_R + 0.1, y_result, 'P + Q', fontsize=12)
    
    # Draw a dotted line to show the reflection
    ax.plot([x_R, x_R], [y_R, y_result], 'g--', linewidth=1.5)
    
    fig.canvas.draw_idle()

def reset(event):
    """Reset all parameters and points"""
    global a, b, P, Q, R, result, point_P, point_Q, point_R, point_result
    a_slider.reset()
    b_slider.reset()
    a = a_slider.val
    b = b_slider.val
    
    # Clear points
    P = None
    Q = None
    R = None
    result = None
    point_P = None
    point_Q = None
    point_R = None
    point_result = None
    
    update_plot()

# Create the main figure
fig, ax = plt.subplots(figsize=(10, 8))
plt.subplots_adjust(bottom=0.25)  # Make room for sliders

# Initial parameters
a = -3
b = 3
x_range = (-4, 4)
y_range = (-4, 4)
P = None
Q = None
R = None
result = None
point_P = None
point_Q = None
point_R = None
point_result = None

# Initial curve
curve_line = update_curve(a, b)

# Add sliders for a and b
ax_a = plt.axes([0.25, 0.15, 0.65, 0.03])
ax_b = plt.axes([0.25, 0.1, 0.65, 0.03])
a_slider = Slider(ax_a, 'a', -10, 10, valinit=a)
b_slider = Slider(ax_b, 'b', -10, 10, valinit=b)

# Add reset button
ax_reset = plt.axes([0.8, 0.02, 0.1, 0.04])
reset_button = Button(ax_reset, 'Reset')

# Connect events
a_slider.on_changed(update_plot)
b_slider.on_changed(update_plot)
reset_button.on_clicked(reset)
fig.canvas.mpl_connect('button_press_event', on_click)

# Instructions text
plt.figtext(0.5, 0.01, "Click on curve to place points P and Q. Reset to clear.", 
            ha="center", fontsize=12, bbox={"facecolor":"orange", "alpha":0.5, "pad":5})

plt.show()