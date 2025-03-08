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
    return abs(y**2 - (x**3 + a*x + b)) < 1e-10

def update_curve(a, b):
    """Update the elliptic curve with new parameters"""
    ax.clear()
    x = np.linspace(x_range[0], x_range[1], 1000)
    valid_indices = x**3 + a*x + b >= 0
    x_valid = x[valid_indices]
    if len(x_valid) > 0:
        y_positive = np.sqrt(x_valid**3 + a*x_valid + b)
        y_negative = -y_positive
        curve_line, = ax.plot(x_valid, y_positive, 'b-', linewidth=2)
        ax.plot(x_valid, y_negative, 'b-', linewidth=2)
    ax.grid(True)
    ax.axhline(y=0, color='k', linestyle='-', alpha=0.3)
    ax.axvline(x=0, color='k', linestyle='-', alpha=0.3)
    ax.set_xlabel('x')
    ax.set_ylabel('y')
    ax.set_title(f'Elliptic Curve: y² = x³ + {a}x + {b}')
    ax.set_aspect('equal', adjustable='box')
    ax.set_xlim(x_range)
    ax.set_ylim(y_range)
    fig.canvas.draw_idle()
    return curve_line if 'curve_line' in locals() else None

def update_plot(val=None):
    """Update the entire plot with new parameters"""
    global a, b, curve_line
    a = a_slider.val
    b = b_slider.val
    curve_line = update_curve(a, b)
    reset_points()
    update_multiplication()
    fig.canvas.draw_idle()

def reset_points():
    """Reset all points"""
    global P, Q, R, result, point_P, point_Q, point_R, point_result, mult_points
    if point_P: point_P.remove()
    if point_Q: point_Q.remove()
    if point_R: point_R.remove()
    if point_result: point_result.remove()
    for mp in mult_points: mp.remove()
    P = None
    Q = None
    R = None
    result = None
    point_P = None
    point_Q = None
    point_R = None
    point_result = None
    mult_points = []
    if 'info_text' in globals() and info_text: info_text.remove()

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
    """Handle click events to select points"""
    global P, Q, point_P, point_Q
    if event.inaxes != ax or curve_line is None:
        return
    x_click = event.xdata
    y_click = event.ydata
    x_curve = np.linspace(x_range[0], x_range[1], 1000)
    valid_indices = x_curve**3 + a*x_curve + b >= 0
    x_valid = x_curve[valid_indices]
    if len(x_valid) == 0:
        return
    x_closest = x_valid[np.argmin(np.abs(x_valid - x_click))]
    y_values = find_y_on_curve(x_closest, a, b)
    if not y_values:
        return
    y_closest = y_values[np.argmin(np.abs(np.array(y_values) - y_click))]
    
    if P is None:
        P = (x_closest, y_closest)
        if point_P: point_P.remove()
        point_P = ax.plot(P[0], P[1], 'ro', markersize=8)[0]
        ax.text(P[0] + 0.1, P[1], 'P', fontsize=12)
        update_multiplication()
    elif Q is None and (x_closest, y_closest) != P:
        Q = (x_closest, y_closest)
        if point_Q: point_Q.remove()
        point_Q = ax.plot(Q[0], Q[1], 'ro', markersize=8)[0]
        ax.text(Q[0] + 0.1, Q[1], 'Q', fontsize=12)
        add_points()
    else:
        reset_points()
        P = (x_closest, y_closest)
        point_P = ax.plot(P[0], P[1], 'ro', markersize=8)[0]
        ax.text(P[0] + 0.1, P[1], 'P', fontsize=12)
        update_multiplication()
    fig.canvas.draw_idle()

def add_points():
    """Add P and Q using elliptic curve addition"""
    global R, result, point_R, point_result, info_text
    if P is None or Q is None:
        return
    x_P, y_P = P
    x_Q, y_Q = Q
    if 'info_text' in globals() and info_text:
        info_text.remove()
    if x_P == x_Q and y_P == -y_Q:
        ax.text((x_P + x_Q)/2, 0, 'P + Q = O (infinity)', fontsize=12)
        info_text = ax.text(0.02, 0.98, 'P + Q = Point at infinity', 
                           transform=ax.transAxes, fontsize=11,
                           bbox=dict(facecolor='yellow', alpha=0.5),
                           verticalalignment='top')
        fig.canvas.draw_idle()
        return
    if x_P == x_Q:
        lambda_val = (3 * x_P**2 + a) / (2 * y_P)
    else:
        lambda_val = (y_Q - y_P) / (x_Q - x_P)
    x_line = np.linspace(x_range[0], x_range[1], 1000)
    y_line = lambda_val * (x_line - x_P) + y_P
    ax.plot(x_line, y_line, 'g-', linewidth=1.5)
    x_R = lambda_val**2 - x_P - x_Q
    y_R = lambda_val * (x_R - x_P) + y_P
    R = (x_R, y_R)
    point_R = ax.plot(x_R, y_R, 'mo', markersize=8)[0]
    ax.text(x_R + 0.1, y_R, 'R', fontsize=12)
    y_result = -y_R
    result = (x_R, y_result)
    point_result = ax.plot(x_R, y_result, 'go', markersize=8)[0]
    ax.text(x_R + 0.1, y_result, 'P + Q', fontsize=12)
    ax.plot([x_R, x_R], [y_R, y_result], 'g--', linewidth=1.5)
    info_text = ax.text(0.02, 0.98, 
                        f'P = ({P[0]:.4f}, {P[1]:.4f})\n'
                        f'Q = ({Q[0]:.4f}, {Q[1]:.4f})\n'
                        f'R = ({x_R:.4f}, {y_R:.4f})\n'
                        f'P + Q = ({result[0]:.4f}, {result[1]:.4f})',
                        transform=ax.transAxes, fontsize=11,
                        bbox=dict(facecolor='yellow', alpha=0.5),
                        verticalalignment='top')
    fig.canvas.draw_idle()

def point_addition(P1, P2, a):
    """Add two points on the elliptic curve"""
    if P1 is None or P2 is None:
        return None
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and y1 == -y2:
        return None  # Point at infinity
    if x1 == x2:
        lambda_val = (3 * x1**2 + a) / (2 * y1)
    else:
        lambda_val = (y2 - y1) / (x2 - x1)
    x3 = lambda_val**2 - x1 - x2
    y3 = lambda_val * (x1 - x3) - y1
    return (x3, y3)

def scalar_multiply(P, k, a):
    """Multiply point P by scalar k using repeated addition"""
    if k <= 0 or P is None:
        return []
    result = P
    points = [P]  # Start with P (1P)
    for _ in range(k - 1):
        result = point_addition(result, P, a)
        if result is None:  # Hit infinity
            break
        points.append(result)
    return points

def update_multiplication(val=None):
    """Update the plot with k * P"""
    global mult_points, info_text
    if P is None:
        return
    k = int(k_slider.val)
    
    # Clear existing multiplication points
    for mp in mult_points:
        mp.remove()
    mult_points = []
    
    # Clear existing info text safely
    if 'info_text' in globals() and info_text is not None:
        try:
            info_text.remove()
        except:
            pass  # Already removed
        info_text = None
    
    # Calculate new points
    points = scalar_multiply(P, k, a)
    for i, point in enumerate(points, 1):
        mp = ax.plot(point[0], point[1], 'co', markersize=6)[0]
        ax.text(point[0] + 0.1, point[1], f'{i}P', fontsize=10)
        mult_points.append(mp)
    
    # Add new info text
    if points:
        info_text = ax.text(0.02, 0.98, 
                          f'P = ({P[0]:.4f}, {P[1]:.4f})\n'
                          f'k = {k}\n'
                          f'kP = ({points[-1][0]:.4f}, {points[-1][1]:.4f})',
                          transform=ax.transAxes, fontsize=11,
                          bbox=dict(facecolor='yellow', alpha=0.5),
                          verticalalignment='top')
    else:
        info_text = ax.text(0.02, 0.98,
                          f'P = ({P[0]:.4f}, {P[1]:.4f})\n'
                          f'k = {k}\n'
                          f'kP = infinity',
                          transform=ax.transAxes, fontsize=11,
                          bbox=dict(facecolor='yellow', alpha=0.5),
                          verticalalignment='top')
    
    fig.canvas.draw_idle()

def reset(event):
    """Reset all parameters and points"""
    global a, b, curve_line
    a_slider.reset()
    b_slider.reset()
    k_slider.reset()
    a = a_slider.val
    b = b_slider.val
    reset_points()  # Reset all points first
    curve_line = update_curve(a, b)  # Update the curve with new a, b values
    fig.canvas.draw_idle()  # Force a redraw

# Global variables
fig, ax = plt.subplots(figsize=(10, 8))
plt.subplots_adjust(bottom=0.25)
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
mult_points = []
info_text = None

curve_line = update_curve(a, b)

# Sliders
ax_a = plt.axes([0.25, 0.15, 0.65, 0.03])
ax_b = plt.axes([0.25, 0.1, 0.65, 0.03])
ax_k = plt.axes([0.25, 0.05, 0.65, 0.03])  # New k slider
a_slider = Slider(ax_a, 'a', -10, 10, valinit=a)
b_slider = Slider(ax_b, 'b', -10, 10, valinit=b)
k_slider = Slider(ax_k, 'k', 1, 10, valinit=1, valstep=1)  # k from 1 to 10

# Reset button
ax_reset = plt.axes([0.8, 0.02, 0.1, 0.04])
reset_button = Button(ax_reset, 'Reset')

# Connect events
a_slider.on_changed(update_plot)
b_slider.on_changed(update_plot)
k_slider.on_changed(update_multiplication)
reset_button.on_clicked(reset)
fig.canvas.mpl_connect('button_press_event', on_click)

plt.figtext(0.5, 0.01, "Click to place P (then Q for addition). Slide k to see k*P.", 
            ha="center", fontsize=12, bbox={"facecolor":"orange", "alpha":0.5, "pad":5})

plt.show()